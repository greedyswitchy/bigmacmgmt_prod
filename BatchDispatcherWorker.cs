using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using Microsoft.Extensions.Options;

namespace ArmDeviceAgent;

public sealed class BatchDispatcherWorker : BackgroundService
{
    private readonly Channel<RawPnpEvent> _channel;
    private readonly SqliteBatchQueue _queue;
    private readonly IHttpClientFactory _httpFactory;
    private readonly AgentOptions _options;
    private readonly ILogger<BatchDispatcherWorker> _logger;
    private readonly string _humanLogPath;

    // История по физическим портам для отлова повторной энумерации (BadUSB / ZeroCD)
    private readonly ConcurrentDictionary<string, (DateTimeOffset SeenAt, string Signature)> _portHistory = new();

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        WriteIndented = false
    };

    public BatchDispatcherWorker(
        Channel<RawPnpEvent> channel,
        SqliteBatchQueue queue,
        IHttpClientFactory httpFactory,
        IOptions<AgentOptions> options,
        ILogger<BatchDispatcherWorker> logger)
    {
        _channel = channel;
        _queue = queue;
        _httpFactory = httpFactory;
        _options = options.Value;
        _logger = logger;
        _humanLogPath = Path.Combine(AppContext.BaseDirectory, "events_human.log");
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var buffer = new List<RawPnpEvent>(_options.MaxBatchSize);
        var window = TimeSpan.FromSeconds(Math.Max(1, _options.BatchWindowSeconds));

        await FlushPendingQueueAsync(stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            if (!await _channel.Reader.WaitToReadAsync(stoppingToken))
                break;

            using var windowCts = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
            windowCts.CancelAfter(window);

            try
            {
                while (buffer.Count < _options.MaxBatchSize)
                {
                    var ev = await _channel.Reader.ReadAsync(windowCts.Token);
                    buffer.Add(ev);
                }
            }
            catch (OperationCanceledException) when (!stoppingToken.IsCancellationRequested)
            {
                // Окно батчинга закрылось — склеиваем события
            }

            if (buffer.Count > 0)
            {
                var batch = await BuildBatchPayloadAsync(buffer, stoppingToken);
                buffer.Clear();

                if (batch.Events.Count > 0)
                {
                    await WriteHumanReadableLogsAsync(batch, stoppingToken);

                    string json = JsonSerializer.Serialize(batch, JsonOpts);
                    await _queue.EnqueueAsync(batch.BatchId, json, stoppingToken);
                    await FlushPendingQueueAsync(stoppingToken);
                }
            }
        }
    }

    private async Task<EventBatchPayload> BuildBatchPayloadAsync(List<RawPnpEvent> rawEvents, CancellationToken ct)
    {
        var aggregated = new List<AggregatedDeviceEvent>();

        // Отфильтровываем системные корневые контроллеры (ROOT_HUB30)
        var filteredEvents = rawEvents
            .Where(e => !e.Device.ResolvedClasses.Contains("RootHub"))
            .ToList();

        // Склеиваем интерфейсы одного устройства: по ContainerId или по базовому физическому порту + VID:PID
        var groups = filteredEvents.GroupBy(e =>
        {
            string baseLoc = DeviceClassifier.GetBasePhysicalLocation(e.Device.PrimaryLocationPath);
            string deviceKey = e.Device.ContainerId != Guid.Empty
                ? e.Device.ContainerId.ToString()
                : (baseLoc != "UNKNOWN_PORT"
                    ? $"{baseLoc}|{e.Device.Vid}:{e.Device.Pid}"
                    : e.Device.InstanceId);

            return new { deviceKey, e.Action, e.TriggerSource };
        });

        foreach (var group in groups)
        {
            var first = group.First();
            var allCompat = group.SelectMany(x => x.Device.CompatibleIds).Distinct().ToArray();

            var resolvedClasses = group
                .SelectMany(x => x.Device.ResolvedClasses)
                .Where(c => c != "Unknown")
                .Distinct()
                .ToArray();
            if (resolvedClasses.Length == 0)
                resolvedClasses = ["Unknown"];

            var instanceIds = group.Select(x => x.Device.InstanceId).Distinct().ToArray();
            string baseLocation = DeviceClassifier.GetBasePhysicalLocation(first.Device.PrimaryLocationPath);

            // Если у родительского узла есть реальный серийник, берём его вместо сгенерированного на интерфейсе
            var realSerialNode = group.FirstOrDefault(x =>
                !x.Device.IsPortGeneratedSerial && !string.IsNullOrWhiteSpace(x.Device.Serial));
            string serial = realSerialNode?.Device.Serial ?? first.Device.Serial;
            bool isPortGenSerial = realSerialNode is null && group.All(x => x.Device.IsPortGeneratedSerial);

            // Проверка на повторную энумерацию (смена VID/PID или класса на одном порту за <= 10 сек)
            string currentSig = $"{first.Device.Vid}:{first.Device.Pid}[{string.Join(",", resolvedClasses)}]";
            bool isReenum = false;
            string? prevSig = null;

            if (first.Action == "DEVICE_CONNECTED" && baseLocation != "UNKNOWN_PORT")
            {
                if (_portHistory.TryGetValue(baseLocation, out var prev) &&
                    (first.Timestamp - prev.SeenAt) <= TimeSpan.FromSeconds(10) &&
                    prev.Signature != currentSig)
                {
                    isReenum = true;
                    prevSig = prev.Signature;
                }
            }

            if (baseLocation != "UNKNOWN_PORT")
            {
                _portHistory[baseLocation] = (first.Timestamp, currentSig);
            }

            DriveAttachment[] drives = (first.Action != "DEVICE_DISCONNECTED" && resolvedClasses.Contains("MassStorage"))
                ? await DeviceClassifier.FindMountedUsbDrivesWithRetryAsync(first.Device.Vid, first.Device.Pid, serial, ct)
                : Array.Empty<DriveAttachment>();

            aggregated.Add(new AggregatedDeviceEvent(
                EventId: Guid.NewGuid(),
                Timestamp: first.Timestamp,
                Action: first.Action,
                TriggerSource: first.TriggerSource,
                ContainerId: first.Device.ContainerId,
                Vid: first.Device.Vid,
                Pid: first.Device.Pid,
                Serial: serial,
                IsPortGeneratedSerial: isPortGenSerial,
                LocationPath: baseLocation,
                InstanceIds: instanceIds,
                CompatibleIds: allCompat,
                DeviceClasses: resolvedClasses,
                MountedDrives: drives,
                IsComposite: instanceIds.Length > 1,
                IsReenumeration: isReenum,
                PreviousDeviceSignature: prevSig
            ));
        }

        return new EventBatchPayload(
            BatchId: Guid.NewGuid(),
            HostName: Environment.MachineName,
            ActiveUser: DeviceClassifier.GetLoggedOnUser(),
            SentAt: DateTimeOffset.UtcNow,
            Events: aggregated
        );
    }

    private async Task WriteHumanReadableLogsAsync(EventBatchPayload batch, CancellationToken ct)
    {
        var lines = new List<string>(batch.Events.Count);

        foreach (var ev in batch.Events)
        {
            string localTime = ev.Timestamp.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");

            string actionLabel = ev.IsReenumeration
                ? "[!] ТРЕВОГА (смена роли / BadUSB)"
                : ev.Action switch
                {
                    "DEVICE_CONNECTED" when ev.TriggerSource == "wake_from_sleep" => "[~] ПОСЛЕ СНА",
                    "DEVICE_CONNECTED" => "[+] ПОДКЛЮЧЕНО",
                    "DEVICE_DISCONNECTED" => "[-] ОТКЛЮЧЕНО",
                    "INITIAL_INVENTORY" => "[=] БЫЛО ПОДКЛЮЧЕНО",
                    _ => $"[{ev.Action}]"
                };

            string deviceTypeRu = DeviceClassifier.FormatClassesRu(ev.DeviceClasses);
            string serialPart = (!ev.IsPortGeneratedSerial && !string.IsNullOrWhiteSpace(ev.Serial))
                ? $"SN: {ev.Serial}"
                : "без серийника";

            string compositePart = ev.IsComposite ? $", составное ({ev.InstanceIds.Length} интерф.)" : "";
            string portPart = DeviceClassifier.FormatShortPort(ev.LocationPath);

            string drivePart = "";
            if (ev.MountedDrives.Length > 0)
            {
                var driveDescriptions = ev.MountedDrives.Select(d =>
                {
                    string meta = string.Join(" ", new[] { d.FileSystem, d.VolumeLabel }.Where(s => !string.IsNullOrWhiteSpace(s)));
                    return string.IsNullOrEmpty(meta) ? d.DriveLetter : $"{d.DriveLetter} ({meta})";
                });
                drivePart = $" | Диск: {string.Join(", ", driveDescriptions)}";
            }

            string reenumPart = ev.IsReenumeration && !string.IsNullOrEmpty(ev.PreviousDeviceSignature)
                ? $" | Было: {ev.PreviousDeviceSignature}"
                : "";

            string message =
                $"{actionLabel}: {deviceTypeRu} [VID:{ev.Vid} PID:{ev.Pid}, {serialPart}{compositePart}]{drivePart} | Порт: {portPart}{reenumPart} | Юзер: {batch.ActiveUser}";

            _logger.LogInformation("{HumanEvent}", message);
            lines.Add($"[{localTime}] {message}");
        }

        try
        {
            await File.AppendAllLinesAsync(_humanLogPath, lines, Encoding.UTF8, ct);
        }
        catch
        {
            // Не роняем агент, если файл временно заблокирован просмотрщиком
        }
    }

    private async Task FlushPendingQueueAsync(CancellationToken ct)
    {
        var client = _httpFactory.CreateClient("BackendClient");
        var pending = await _queue.PeekOldestAsync(20, ct);

        foreach (var item in pending)
        {
            try
            {
                using var content = new StringContent(item.PayloadJson, Encoding.UTF8, "application/json");
                using var response = await client.PostAsync(_options.BackendBatchUrl, content, ct);

                if (response.IsSuccessStatusCode)
                {
                    await _queue.DeleteAsync(item.RowId, ct);
                    _logger.LogInformation("Батч {BatchId} успешно доставлен на сервер.", item.BatchId);
                }
                else
                {
                    _logger.LogWarning("Сервер вернул HTTP {StatusCode}. Батч {BatchId} оставлен в очереди SQLite.",
                        (int)response.StatusCode, item.BatchId);
                    break;
                }
            }
            catch (Exception ex) when (!ct.IsCancellationRequested)
            {
                _logger.LogWarning("Сервер недоступен ({Message}). События сохранены локально в SQLite.",
                    ex.Message);
                break;
            }
        }
    }
}
