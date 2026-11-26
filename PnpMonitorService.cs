using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Threading.Channels;
using static ArmDeviceAgent.PnpNative;

namespace ArmDeviceAgent;

public sealed class PnpMonitorService : BackgroundService
{
    private readonly Channel<RawPnpEvent> _eventChannel;
    private readonly ILogger<PnpMonitorService> _logger;

    private readonly ConcurrentDictionary<string, DeviceProperties> _activeDevices =
        new(StringComparer.OrdinalIgnoreCase);

    private PCM_NOTIFY_CALLBACK? _pnpCallback;
    private DeviceNotifyCallbackRoutine? _powerCallback;
    private IntPtr _pnpNotifyHandle = IntPtr.Zero;
    private IntPtr _powerNotifyHandle = IntPtr.Zero;

    private DateTimeOffset _lastWakeTimestamp = DateTimeOffset.MinValue;
    private bool _usePollingFallback = false;

    public PnpMonitorService(Channel<RawPnpEvent> eventChannel, ILogger<PnpMonitorService> logger)
    {
        _eventChannel = eventChannel;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        RegisterPowerNotifications();
        RegisterPnpNotifications();

        // Первичный скан подключенных устройств при старте
        ScanCurrentDevices(isInitial: true);

        try
        {
            if (_usePollingFallback)
            {
                // Резервный цикл, если агент запущен без прав Администратора
                while (!stoppingToken.IsCancellationRequested)
                {
                    await Task.Delay(TimeSpan.FromSeconds(2), stoppingToken);
                    ScanCurrentDevices(isInitial: false);
                }
            }
            else
            {
                await Task.Delay(Timeout.Infinite, stoppingToken);
            }
        }
        catch (OperationCanceledException)
        {
            // Штатная остановка службы
        }
    }

    private void RegisterPnpNotifications()
    {
        try
        {
            _pnpCallback = OnPnpEventCallback;
            var filter = CM_NOTIFY_FILTER.CreateAllDeviceInstances();

            uint status = CM_Register_Notification(ref filter, IntPtr.Zero, _pnpCallback, out _pnpNotifyHandle);
            if (status != 0)
            {
                _usePollingFallback = true;
                _logger.LogWarning(
                    "CM_Register_Notification вернул код {Status} (нужны права Администратора или запуск как службы). Включён резервный режим опроса раз в 2 сек.",
                    status);
            }
            else
            {
                _logger.LogInformation("Real-time PnP kernel notifications registered.");
            }
        }
        catch (Exception ex)
        {
            _usePollingFallback = true;
            _logger.LogWarning(ex, "Ошибка подписки на PnP-уведомления. Включён резервный режим опроса.");
        }
    }

    private void RegisterPowerNotifications()
    {
        try
        {
            _powerCallback = OnPowerEventCallback;
            var param = new DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS
            {
                Callback = _powerCallback,
                Context = IntPtr.Zero
            };

            PowerRegisterSuspendResumeNotification(DEVICE_NOTIFY_CALLBACK, ref param, out _powerNotifyHandle);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Не удалось подписаться на события питания (не критично).");
        }
    }

    private void ScanCurrentDevices(bool isInitial)
    {
        IntPtr devInfoSet = SetupDiGetClassDevsW(IntPtr.Zero, "USB", IntPtr.Zero, DIGCF_PRESENT | DIGCF_ALLCLASSES);
        if (devInfoSet == new IntPtr(-1)) return;

        var currentSeenIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        try
        {
            var devInfoData = new SP_DEVINFO_DATA { cbSize = (uint)Marshal.SizeOf<SP_DEVINFO_DATA>() };
            for (uint i = 0; SetupDiEnumDeviceInfo(devInfoSet, i, ref devInfoData); i++)
            {
                var sb = new System.Text.StringBuilder(512);
                if (!SetupDiGetDeviceInstanceIdW(devInfoSet, ref devInfoData, sb, sb.Capacity, out _))
                    continue;

                string instanceId = sb.ToString();
                currentSeenIds.Add(instanceId);

                if (!_activeDevices.ContainsKey(instanceId))
                {
                    var props = ReadDevicePropertiesFromSet(devInfoSet, ref devInfoData, instanceId);
                    if (_activeDevices.TryAdd(instanceId, props))
                    {
                        _eventChannel.Writer.TryWrite(new RawPnpEvent(
                            Timestamp: DateTimeOffset.UtcNow,
                            Action: isInitial ? "INITIAL_INVENTORY" : "DEVICE_CONNECTED",
                            TriggerSource: isInitial ? "boot_inventory" : "polling_fallback",
                            Device: props
                        ));
                    }
                }
            }

            if (isInitial)
            {
                _logger.LogInformation("Initial inventory completed: {Count} USB device nodes cached.", _activeDevices.Count);
            }
            else
            {
                // Проверяем отключенные устройства в режиме polling
                foreach (var existingId in _activeDevices.Keys)
                {
                    if (!currentSeenIds.Contains(existingId))
                    {
                        HandleDeviceRemoval(existingId);
                    }
                }
            }
        }
        finally
        {
            SetupDiDestroyDeviceInfoList(devInfoSet);
        }
    }

    private uint OnPowerEventCallback(IntPtr context, uint type, IntPtr setting)
    {
        if (type == PBT_APMRESUMESUSPEND || type == PBT_APMRESUMEAUTOMATIC)
        {
            _lastWakeTimestamp = DateTimeOffset.UtcNow;
            _logger.LogInformation("System wake detected; marking subsequent USB re-enumerations.");
        }
        return 0;
    }

    private uint OnPnpEventCallback(IntPtr hNotify, IntPtr context, uint action, IntPtr eventData, uint eventDataSize)
    {
        if (eventData == IntPtr.Zero || eventDataSize <= 8)
            return 0;

        uint filterType = (uint)Marshal.ReadInt32(eventData, 0);
        if (filterType != CM_NOTIFY_FILTER_TYPE_DEVICEINSTANCE)
            return 0;

        string? instanceId = Marshal.PtrToStringUni(IntPtr.Add(eventData, 8));
        if (string.IsNullOrWhiteSpace(instanceId) ||
            !instanceId.StartsWith("USB\\", StringComparison.OrdinalIgnoreCase))
        {
            return 0;
        }

        if (action == CM_NOTIFY_ACTION_DEVICEINSTANCEENUMERATED ||
            action == CM_NOTIFY_ACTION_DEVICEINSTANCESTARTED)
        {
            _ = Task.Run(async () =>
            {
                await Task.Delay(150);
                HandleDeviceArrival(instanceId);
            });
        }
        else if (action == CM_NOTIFY_ACTION_DEVICEINSTANCEREMOVED)
        {
            HandleDeviceRemoval(instanceId);
        }

        return 0;
    }

    private void HandleDeviceArrival(string instanceId)
    {
        if (_activeDevices.ContainsKey(instanceId))
            return;

        var props = QuerySingleDeviceProperties(instanceId);
        if (props is null)
            return;

        if (_activeDevices.TryAdd(instanceId, props))
        {
            string trigger = (DateTimeOffset.UtcNow - _lastWakeTimestamp) < TimeSpan.FromSeconds(5)
                ? "wake_from_sleep"
                : "hotplug";

            _eventChannel.Writer.TryWrite(new RawPnpEvent(
                Timestamp: DateTimeOffset.UtcNow,
                Action: "DEVICE_CONNECTED",
                TriggerSource: trigger,
                Device: props
            ));
        }
    }

    private void HandleDeviceRemoval(string instanceId)
    {
        if (_activeDevices.TryRemove(instanceId, out var cachedProps))
        {
            _eventChannel.Writer.TryWrite(new RawPnpEvent(
                Timestamp: DateTimeOffset.UtcNow,
                Action: "DEVICE_DISCONNECTED",
                TriggerSource: _usePollingFallback ? "polling_fallback" : "hotplug",
                Device: cachedProps
            ));
        }
    }

    private static DeviceProperties? QuerySingleDeviceProperties(string instanceId)
    {
        IntPtr devInfoSet = SetupDiCreateDeviceInfoList(IntPtr.Zero, IntPtr.Zero);
        if (devInfoSet == new IntPtr(-1)) return null;

        try
        {
            var devInfoData = new SP_DEVINFO_DATA { cbSize = (uint)Marshal.SizeOf<SP_DEVINFO_DATA>() };
            if (!SetupDiOpenDeviceInfoW(devInfoSet, instanceId, IntPtr.Zero, 0, ref devInfoData))
                return null;

            return ReadDevicePropertiesFromSet(devInfoSet, ref devInfoData, instanceId);
        }
        finally
        {
            SetupDiDestroyDeviceInfoList(devInfoSet);
        }
    }

    private static DeviceProperties ReadDevicePropertiesFromSet(
        IntPtr devInfoSet,
        ref SP_DEVINFO_DATA devInfoData,
        string instanceId)
    {
        string[] compatIds = ReadStringListProperty(devInfoSet, ref devInfoData, DEVPKEY_Device_CompatibleIds);
        string[] locPaths = ReadStringListProperty(devInfoSet, ref devInfoData, DEVPKEY_Device_LocationPaths);
        string[] locInfo = ReadStringListProperty(devInfoSet, ref devInfoData, DEVPKEY_Device_LocationInfo);
        Guid containerId = ReadGuidProperty(devInfoSet, ref devInfoData, DEVPKEY_Device_ContainerId);

        return DeviceClassifier.BuildProperties(instanceId, compatIds, containerId, locPaths, locInfo);
    }

    public override void Dispose()
    {
        if (_pnpNotifyHandle != IntPtr.Zero)
            CM_Unregister_Notification(_pnpNotifyHandle);

        if (_powerNotifyHandle != IntPtr.Zero)
            PowerUnregisterSuspendResumeNotification(_powerNotifyHandle);

        base.Dispose();
    }
}