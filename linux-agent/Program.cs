using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Data.Sqlite;

namespace UsbMonitorAgent;

internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        if (!OperatingSystem.IsLinux())
        {
            Console.Error.WriteLine("[ERROR] Агент предназначен для запуска под Linux (требуются sysfs и udev).");
            return 1;
        }

        string dbPath = args.Length > 0 ? args[0] : "usb_agent.db";
        using var cts = new CancellationTokenSource();

        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            Console.WriteLine("\n[AGENT] Получен сигнал остановки (SIGINT), завершаем работу...");
            cts.Cancel();
        };

        Console.WriteLine("=== Linux USB Monitoring Agent (Detect-Only Prototype) ===");
        Console.WriteLine($"[INIT] База событий: {Path.GetFullPath(dbPath)}");

        using var store = new SqliteEventStore(dbPath);
        var engine = new SecurityCorrelationEngine(store);

        // ШАГ 1: Первичная полная инвентаризация через /sys/bus/usb/devices
        // Ловит устройства, подключённые ДО загрузки ОС или старта агента.
        Console.WriteLine("[INIT] Запуск первичного обхода /sys/bus/usb/devices...");
        var initialDevices = SysfsInventoryScanner.Scan();
        foreach (var device in initialDevices)
        {
            engine.RegisterInitialDevice(device);
        }
        Console.WriteLine($"[INIT] Инвентаризация завершена. Найдено физических USB-устройств: {initialDevices.Count}");
        Console.WriteLine("[MONITOR] Подписка на поток событий udev (Ctrl+C для выхода)...\n");

        // ШАГ 2: Мониторинг в реальном времени через поток udev
        var monitor = new UdevMonitorService();
        try
        {
            await monitor.RunAsync(ev => engine.ProcessUdevEvent(ev), cts.Token);
        }
        catch (OperationCanceledException)
        {
            // Штатная остановка по Ctrl+C
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[FATAL] Ошибка мониторинга: {ex.Message}");
            return 2;
        }

        Console.WriteLine("[AGENT] Работа завершена корректно.");
        return 0;
    }
}

#region Модели данных

/// <summary>
/// Состояние одного ФИЗИЧЕСКОГО USB-устройства (склеивает все интерфейсы :1.0, :1.1 и дочерние узлы block/input/net).
/// </summary>
internal sealed class DeviceState
{
    public required string PhysicalPortPath { get; init; } // Например: /devices/.../usb1/1-2 (или sysfs 1-2)
    public string SysName { get; set; } = "";              // Например: 1-2 или 1-2.3
    public string IdPath { get; set; } = "";               // Физический порт из udev (аналог LocationPaths)
    public string Vid { get; set; } = "????";
    public string Pid { get; set; } = "????";
    public string Serial { get; set; } = "";
    public string VendorName { get; set; } = "";
    public string ModelName { get; set; } = "";
    public string MaxPower { get; set; } = "";             // Заявленное потребление (не измеренное!)
    public string SpeedMbps { get; set; } = "";
    public bool Authorized { get; set; } = true;
    public HashSet<string> RawInterfaces { get; } = new(StringComparer.OrdinalIgnoreCase); // Формат: 080650
    public HashSet<string> HumanClasses { get; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> BlockDevices { get; } = new(StringComparer.OrdinalIgnoreCase);
    public string? FilesystemInfo { get; set; }
    public string? NetworkInterface { get; set; }
    public bool IsKeyboardDetected { get; set; }
    public DateTime FirstSeenUtc { get; init; } = DateTime.UtcNow;

    // Флаги, чтобы не спамить одинаковыми алертами при доприходе дочерних событий
    public HashSet<string> FiredAlertRules { get; } = new();

    public string FormatClasses() => HumanClasses.Count > 0
        ? string.Join(", ", HumanClasses.OrderBy(x => x))
        : "Unknown";

    public string FormatRawInterfaces() => RawInterfaces.Count > 0
        ? ":" + string.Join(":", RawInterfaces.OrderBy(x => x)) + ":"
        : "";
}

internal sealed record DisconnectedRecord(
    DateTime DisconnectedAtUtc,
    string Vid,
    string Pid,
    HashSet<string> RawInterfaces
);

internal sealed record UdevEvent(
    string Action,
    string DevPath,
    string Subsystem,
    Dictionary<string, string> Properties
);

#endregion

#region Классификатор по USB класс-кодам

internal static class UsbClassClassifier
{
    // Классификация строится по bInterfaceClass (2 первых hex-символа), а не по VID/PID
    private static readonly Dictionary<string, string> ClassMap = new(StringComparer.OrdinalIgnoreCase)
    {
        ["01"] = "Audio",
        ["02"] = "CDC-Comm (Modem/Net)",
        ["03"] = "HID (Input)",
        ["05"] = "Physical",
        ["06"] = "Imaging (PTP/MTP)",
        ["07"] = "Printer",
        ["08"] = "Mass Storage (MSC)",
        ["09"] = "USB Hub",
        ["0a"] = "CDC-Data",
        ["0b"] = "SmartCard (CCID)",
        ["0d"] = "Content Security",
        ["0e"] = "Video (UVC)",
        ["0f"] = "Personal Healthcare",
        ["dc"] = "Diagnostic",
        ["e0"] = "Wireless (BT/RNDIS)",
        ["ef"] = "Misc (IAD/Composite/RNDIS)",
        ["fe"] = "App-Specific (DFU/IrDA)",
        ["ff"] = "Vendor-Specific"
    };

    /// <summary>
    /// Разбирает строку вида ":080650:030101:" -> набор (class/subclass/proto) и человекочитаемых классов.
    /// </summary>
    public static void ApplyInterfacesString(string? idUsbInterfaces, DeviceState target)
    {
        if (string.IsNullOrWhiteSpace(idUsbInterfaces))
            return;

        var tokens = idUsbInterfaces.Split(':', StringSplitOptions.RemoveEmptyEntries);
        foreach (var token in tokens)
        {
            if (token.Length < 2) continue;
            target.RawInterfaces.Add(token.ToLowerInvariant());
            target.HumanClasses.Add(ClassifyTriplet(token));
        }
    }

    public static string ClassifyTriplet(string hexTriplet)
    {
        string normalized = hexTriplet.ToLowerInvariant();
        string cls = normalized.Length >= 2 ? normalized[..2] : "??";
        string sub = normalized.Length >= 4 ? normalized[2..4] : "??";
        string proto = normalized.Length >= 6 ? normalized[4..6] : "??";

        // Уточнения для наиболее критичных с точки зрения ИБ подклассов
        if (cls == "03" && sub == "01" && proto == "01") return "HID-Keyboard";
        if (cls == "03" && sub == "01" && proto == "02") return "HID-Mouse";
        if (cls == "08" && sub == "06") return "Mass Storage (SCSI)";
        if (cls == "02" && sub == "02") return "CDC-ACM (Serial/COM)";
        if (cls == "02" && (sub == "06" || sub == "0d")) return "USB-Ethernet (CDC/NCM)";
        if (cls == "ef" && sub == "04" && proto == "01") return "USB-Ethernet (RNDIS)";
        if (cls == "fe" && sub == "01") return "DFU (Firmware Update)";

        return ClassMap.TryGetValue(cls, out var name) ? name : $"Class_0x{cls}";
    }

    public static bool HasClassPrefix(DeviceState state, string twoHexPrefix) =>
        state.RawInterfaces.Any(r => r.StartsWith(twoHexPrefix, StringComparison.OrdinalIgnoreCase));

    public static bool IsNetworkClass(DeviceState state) =>
        state.RawInterfaces.Any(r =>
            r.StartsWith("0206", StringComparison.OrdinalIgnoreCase) || // CDC ECM
            r.StartsWith("020d", StringComparison.OrdinalIgnoreCase) || // CDC NCM
            r.StartsWith("ef0401", StringComparison.OrdinalIgnoreCase) || // RNDIS
            r.StartsWith("e00103", StringComparison.OrdinalIgnoreCase));  // RNDIS wireless
}

#endregion

#region 1. Первичный обход sysfs

internal static class SysfsInventoryScanner
{
    private const string UsbDevicesRoot = "/sys/bus/usb/devices";

    public static List<DeviceState> Scan()
    {
        var result = new List<DeviceState>();
        if (!Directory.Exists(UsbDevicesRoot))
            return result;

        foreach (var entryPath in Directory.GetDirectories(UsbDevicesRoot))
        {
            string sysName = Path.GetFileName(entryPath);

            // Пропускаем root-хабы (usb1, usb2) и дочерние интерфейсы (1-2:1.0) —
            // интерфейсы соберём внутри родительской папки, чтобы сразу склеить составное устройство.
            if (sysName.StartsWith("usb", StringComparison.OrdinalIgnoreCase) || sysName.Contains(':'))
                continue;

            try
            {
                string? vid = ReadSysfsFile(entryPath, "idVendor");
                string? pid = ReadSysfsFile(entryPath, "idProduct");
                if (vid is null || pid is null)
                    continue;

                // Разворачиваем симлинк, чтобы получить каноничный DEVPATH (как в udev)
                string realPath = ResolveDevPath(entryPath);

                var state = new DeviceState
                {
                    PhysicalPortPath = realPath,
                    SysName = sysName,
                    Vid = vid,
                    Pid = pid,
                    Serial = ReadSysfsFile(entryPath, "serial") ?? "",
                    VendorName = ReadSysfsFile(entryPath, "manufacturer") ?? "",
                    ModelName = ReadSysfsFile(entryPath, "product") ?? "",
                    MaxPower = ReadSysfsFile(entryPath, "bMaxPower") ?? "",
                    SpeedMbps = ReadSysfsFile(entryPath, "speed") ?? "",
                    Authorized = ReadSysfsFile(entryPath, "authorized") != "0"
                };

                // Собираем все интерфейсы (1-2:1.0, 1-2:1.1...) внутри физического устройства
                foreach (var subDir in Directory.GetDirectories(entryPath, $"{sysName}:*"))
                {
                    string cls = ReadSysfsFile(subDir, "bInterfaceClass") ?? "00";
                    string sub = ReadSysfsFile(subDir, "bInterfaceSubClass") ?? "00";
                    string proto = ReadSysfsFile(subDir, "bInterfaceProtocol") ?? "00";
                    string triplet = $"{cls}{sub}{proto}".ToLowerInvariant();

                    state.RawInterfaces.Add(triplet);
                    state.HumanClasses.Add(UsbClassClassifier.ClassifyTriplet(triplet));
                }

                // Фоллбек на bDeviceClass, если интерфейсы не прочитались
                if (state.RawInterfaces.Count == 0)
                {
                    string devClass = ReadSysfsFile(entryPath, "bDeviceClass") ?? "00";
                    if (devClass != "00")
                    {
                        string triplet = $"{devClass}0000";
                        state.RawInterfaces.Add(triplet);
                        state.HumanClasses.Add(UsbClassClassifier.ClassifyTriplet(triplet));
                    }
                }

                result.Add(state);
            }
            catch (IOException)
            {
                // Устройство могли выдернуть прямо во время обхода — игнорируем
            }
        }

        return result;
    }

    private static string? ReadSysfsFile(string dir, string fileName)
    {
        string path = Path.Combine(dir, fileName);
        if (!File.Exists(path)) return null;
        return File.ReadAllText(path).Trim();
    }

    private static string ResolveDevPath(string sysfsSymlinkPath)
    {
        var info = new DirectoryInfo(sysfsSymlinkPath);
        string full = info.ResolveLinkTarget(returnFinalTarget: true)?.FullName ?? sysfsSymlinkPath;
        // Приводим "/sys/devices/..." к формату udev DEVPATH "/devices/..."
        return full.StartsWith("/sys/", StringComparison.Ordinal) ? full[4..] : full;
    }
}

#endregion

#region 2. Подписка на поток udev (аналог libudev monitor)

internal sealed class UdevMonitorService
{
    // Пример заголовка: UDEV  [12345.678901] add      /devices/pci0000:00/.../usb1/1-2 (usb)
    private static readonly Regex HeaderRegex = new(
        @"^UDEV\s+\[[^\]]+\]\s+(?<action>\S+)\s+(?<devpath>\S+)\s+\((?<subsys>[^)]+)\)",
        RegexOptions.Compiled);

    public async Task RunAsync(Action<UdevEvent> onEvent, CancellationToken ct)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "udevadm",
            Arguments = "monitor --udev --property",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8
        };

        using var proc = Process.Start(psi)
            ?? throw new InvalidOperationException("Не удалось запустить udevadm.");

        // Гарантированно убиваем дочерний процесс при отмене токена
        using var reg = ct.Register(() =>
        {
            try { if (!proc.HasExited) proc.Kill(entireProcessTree: true); } catch { }
        });

        string? curAction = null;
        string? curDevPath = null;
        string? curSubsys = null;
        var props = new Dictionary<string, string>(StringComparer.Ordinal);

        while (!ct.IsCancellationRequested)
        {
            string? line = await proc.StandardOutput.ReadLineAsync(ct);
            if (line is null) break;

            // Пустая строка завершает блок одного события udev
            if (string.IsNullOrWhiteSpace(line))
            {
                if (curAction is not null && curDevPath is not null && curSubsys is not null)
                {
                    onEvent(new UdevEvent(curAction, curDevPath, curSubsys, new Dictionary<string, string>(props)));
                }
                curAction = null;
                curDevPath = null;
                curSubsys = null;
                props.Clear();
                continue;
            }

            if (curAction is null)
            {
                var m = HeaderRegex.Match(line);
                if (m.Success)
                {
                    curAction = m.Groups["action"].Value;
                    curDevPath = m.Groups["devpath"].Value;
                    curSubsys = m.Groups["subsys"].Value;
                }
                continue;
            }

            int eqIdx = line.IndexOf('=');
            if (eqIdx > 0)
            {
                props[line[..eqIdx]] = line[(eqIdx + 1)..];
            }
        }
    }
}

#endregion

#region 3. Движок корреляции, дедупликации и детекта аномалий

internal sealed class SecurityCorrelationEngine
{
    private static readonly Regex UsbRootSegment = new(@"^usb\d+$", RegexOptions.Compiled);
    private static readonly Regex UsbDeviceSegment = new(@"^\d+-\d+(\.\d+)*$", RegexOptions.Compiled);
    private static readonly TimeSpan ReEnumerationWindow = TimeSpan.FromSeconds(15);

    private readonly SqliteEventStore _store;
    private readonly ConcurrentDictionary<string, DeviceState> _activeDevices = new();
    private readonly ConcurrentDictionary<string, DisconnectedRecord> _recentlyDisconnected = new();

    public SecurityCorrelationEngine(SqliteEventStore store)
    {
        _store = store;
    }

    public void RegisterInitialDevice(DeviceState state)
    {
        _activeDevices[state.PhysicalPortPath] = state;
        _store.SaveDeviceEvent("INVENTORY", state, null);

        Console.WriteLine(
            $"  [INVENTORY] Порт={state.SysName} | {state.Vid}:{state.Pid} | " +
            $"Серийник={(string.IsNullOrEmpty(state.Serial) ? "<нет>" : state.Serial)} | " +
            $"Классы=[{state.FormatClasses()}] | {state.VendorName} {state.ModelName}".Trim());

        EvaluateSecurityRules(state, isInitialScan: true);
    }

    public void ProcessUdevEvent(UdevEvent ev)
    {
        // Нас интересуют только события, физически растущие из USB-шины
        string? physicalPortPath = ExtractPhysicalUsbDevPath(ev.DevPath, out string sysName);
        if (physicalPortPath is null)
            return;

        // 1) Событие физического подключения USB-устройства
        if (ev.Subsystem == "usb" &&
            ev.Properties.GetValueOrDefault("DEVTYPE") == "usb_device" &&
            ev.Action == "add")
        {
            HandlePhysicalConnect(physicalPortPath, sysName, ev.Properties);
            return;
        }

        // 2) Событие физического отключения USB-устройства
        if (ev.Subsystem == "usb" &&
            ev.Properties.GetValueOrDefault("DEVTYPE") == "usb_device" &&
            ev.Action == "remove")
        {
            HandlePhysicalDisconnect(physicalPortPath);
            return;
        }

        // 3) Дообогащение уже известного физического устройства из дочерних подсистем
        // (интерфейсы, блочные тома, клавиатуры/мыши, сетевые интерфейсы) — БЕЗ дублирования алертов!
        if (ev.Action is "add" or "change" or "bind" &&
            _activeDevices.TryGetValue(physicalPortPath, out var existing))
        {
            EnrichFromChildEvent(existing, ev);
        }
    }

    private void HandlePhysicalConnect(string portPath, string sysName, Dictionary<string, string> props)
    {
        var state = new DeviceState
        {
            PhysicalPortPath = portPath,
            SysName = sysName,
            IdPath = props.GetValueOrDefault("ID_PATH", ""),
            Vid = props.GetValueOrDefault("ID_VENDOR_ID", "????"),
            Pid = props.GetValueOrDefault("ID_MODEL_ID", "????"),
            Serial = props.GetValueOrDefault("ID_SERIAL_SHORT", ""),
            VendorName = props.GetValueOrDefault("ID_VENDOR_FROM_DATABASE")
                         ?? props.GetValueOrDefault("ID_VENDOR", ""),
            ModelName = props.GetValueOrDefault("ID_MODEL_FROM_DATABASE")
                        ?? props.GetValueOrDefault("ID_MODEL", "")
        };

        // Главный дешёвый источник классов: свойство ID_USB_INTERFACES из udev
        UsbClassClassifier.ApplyInterfacesString(props.GetValueOrDefault("ID_USB_INTERFACES"), state);

        // Дочитываем поля, которых нет в udev-событии, напрямую из sysfs
        string sysfsDir = "/sys" + portPath;
        if (Directory.Exists(sysfsDir))
        {
            try
            {
                string powerPath = Path.Combine(sysfsDir, "bMaxPower");
                if (File.Exists(powerPath)) state.MaxPower = File.ReadAllText(powerPath).Trim();
            }
            catch { }
        }

        _activeDevices[portPath] = state;
        _store.SaveDeviceEvent("CONNECT", state, props.GetValueOrDefault("DEVNAME"));

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine(
            $"[+ CONNECT] {DateTime.Now:HH:mm:ss} | Порт={state.SysName} ({state.IdPath}) | " +
            $"{state.Vid}:{state.Pid} | SN={(string.IsNullOrEmpty(state.Serial) ? "<нет>" : state.Serial)} | " +
            $"Классы=[{state.FormatClasses()}] | {state.VendorName} {state.ModelName}");
        Console.ResetColor();

        // Проверка на повторную энумерацию (ZeroCD / DFU / многостадийный BadUSB)
        CheckReEnumeration(state);

        // Проверка остальных эвристик
        EvaluateSecurityRules(state, isInitialScan: false);
    }

    private void HandlePhysicalDisconnect(string portPath)
    {
        if (!_activeDevices.TryRemove(portPath, out var removed))
            return;

        // Запоминаем порт в кэше недавних отключений для ловли повторной энумерации
        _recentlyDisconnected[portPath] = new DisconnectedRecord(
            DateTime.UtcNow,
            removed.Vid,
            removed.Pid,
            new HashSet<string>(removed.RawInterfaces, StringComparer.OrdinalIgnoreCase)
        );

        _store.SaveDeviceEvent("DISCONNECT", removed, null);

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine(
            $"[- REMOVE ] {DateTime.Now:HH:mm:ss} | Порт={removed.SysName} | " +
            $"{removed.Vid}:{removed.Pid} | {removed.VendorName} {removed.ModelName}");
        Console.ResetColor();
    }

    private void EnrichFromChildEvent(DeviceState state, UdevEvent ev)
    {
        bool enriched = false;

        // Обогащение классов, если прилетели на уровне интерфейса или дочернего узла
        if (ev.Properties.TryGetValue("ID_USB_INTERFACES", out var ifaces))
        {
            int before = state.RawInterfaces.Count;
            UsbClassClassifier.ApplyInterfacesString(ifaces, state);
            if (state.RawInterfaces.Count > before) enriched = true;
        }

        // Информация о файловой системе (blkid) — доступна ДАЖЕ БЕЗ МОНТИРОВАНИЯ ТОМА!
        if (ev.Subsystem == "block")
        {
            string? devName = ev.Properties.GetValueOrDefault("DEVNAME");
            string? fsType = ev.Properties.GetValueOrDefault("ID_FS_TYPE");
            string? fsLabel = ev.Properties.GetValueOrDefault("ID_FS_LABEL");
            string? fsUuid = ev.Properties.GetValueOrDefault("ID_FS_UUID");

            if (!string.IsNullOrEmpty(devName) && state.BlockDevices.Add(devName) && !string.IsNullOrEmpty(fsType))
            {
                state.FilesystemInfo = $"{devName} ({fsType}, label='{fsLabel}', uuid={fsUuid})";
                enriched = true;
                Console.WriteLine($"  [~ BLOCK] Порт={state.SysName} -> Том {state.FilesystemInfo}");
            }
        }

        // Подсистема ввода (input_id): подтверждение, что устройство реально представляется клавиатурой
        if (ev.Subsystem == "input" && ev.Properties.GetValueOrDefault("ID_INPUT_KEYBOARD") == "1")
        {
            if (!state.IsKeyboardDetected)
            {
                state.IsKeyboardDetected = true;
                state.HumanClasses.Add("HID-Keyboard");
                enriched = true;
                Console.WriteLine($"  [~ INPUT] Порт={state.SysName} -> Обнаружен ввод с клавиатуры ({ev.Properties.GetValueOrDefault("DEVNAME")})");
            }
        }

        // Сетевая подсистема (RNDIS / CDC-Ethernet)
        if (ev.Subsystem == "net")
        {
            string? iface = ev.Properties.GetValueOrDefault("INTERFACE");
            if (!string.IsNullOrEmpty(iface) && state.NetworkInterface != iface)
            {
                state.NetworkInterface = iface;
                enriched = true;
                Console.WriteLine($"  [~ NET  ] Порт={state.SysName} -> Новый сетевой интерфейс {iface}");
            }
        }

        if (enriched)
        {
            _store.SaveDeviceEvent("ENRICH", state, ev.Properties.GetValueOrDefault("DEVNAME"));
            EvaluateSecurityRules(state, isInitialScan: false);
        }
    }

    private void CheckReEnumeration(DeviceState current)
    {
        if (!_recentlyDisconnected.TryRemove(current.PhysicalPortPath, out var prev))
            return;

        var delta = DateTime.UtcNow - prev.DisconnectedAtUtc;
        if (delta > ReEnumerationWindow)
            return;

        bool idChanged = !string.Equals(prev.Vid, current.Vid, StringComparison.OrdinalIgnoreCase) ||
                         !string.Equals(prev.Pid, current.Pid, StringComparison.OrdinalIgnoreCase);

        bool classesChanged = !prev.RawInterfaces.SetEquals(current.RawInterfaces);

        if (idChanged || classesChanged)
        {
            RaiseAlert(
                severity: "HIGH",
                ruleCode: "RE_ENUMERATION_DESCRIPTOR_SHIFT",
                state: current,
                message: $"Повторная энумерация на порту {current.SysName} через {delta.TotalSeconds:F1}с со сменой дескрипторов! " +
                         $"Было {prev.Vid}:{prev.Pid}, стало {current.Vid}:{current.Pid} (классы: [{current.FormatClasses()}]). " +
                         $"Возможен ZeroCD, DFU или многостадийный BadUSB.");
        }
    }

    private void EvaluateSecurityRules(DeviceState state, bool isInitialScan)
    {
        bool hasStorage = UsbClassClassifier.HasClassPrefix(state, "08");
        bool hasHid = UsbClassClassifier.HasClassPrefix(state, "03") || state.IsKeyboardDetected;
        bool hasNet = UsbClassClassifier.IsNetworkClass(state) || !string.IsNullOrEmpty(state.NetworkInterface);

        // Правило 1: Составное устройство Storage + HID или Network + HID (классический паттерн BadUSB / Bash Bunny)
        if (hasHid && (hasStorage || hasNet))
        {
            RaiseAlert(
                severity: "CRITICAL",
                ruleCode: "COMPOSITE_HID_ANOMALY",
                state: state,
                message: $"Составное устройство на порту {state.SysName} совмещает HID-ввод с накопителем/сетью " +
                         $"([{state.FormatClasses()}]). Высокий риск BadUSB!");
        }

        // Правило 2: Подключение USB-сетевой карты (риск перехвата трафика через DHCP и метрику маршрута)
        if (hasNet)
        {
            RaiseAlert(
                severity: "HIGH",
                ruleCode: "USB_NETWORK_INTERFACE",
                state: state,
                message: $"Обнаружен USB сетевой адаптер ({state.NetworkInterface ?? "ожидает имя"}) на порту {state.SysName}. " +
                         $"Проверьте маршрутизацию и политики NetworkManager.");
        }

        // Правило 3: Съёмный накопитель без серийного номера (невозможно однозначно трекать сквозь порты)
        if (hasStorage && string.IsNullOrEmpty(state.Serial))
        {
            RaiseAlert(
                severity: "MEDIUM",
                ruleCode: "MSC_WITHOUT_SERIAL",
                state: state,
                message: $"USB-накопитель {state.Vid}:{state.Pid} на порту {state.SysName} не передал iSerialNumber. " +
                         $"Возможна подмена или дешёвый контроллер; трекинг ограничен физическим портом.");
        }

        // Правило 4: Новая HID-клавиатура в реальном времени (напоминание о гонке со временем)
        if (!isInitialScan && state.IsKeyboardDetected)
        {
            RaiseAlert(
                severity: "INFO",
                ruleCode: "HOTPLUG_HID_KEYBOARD",
                state: state,
                message: $"Горячее подключение USB-клавиатуры на порту {state.SysName} ({state.Vid}:{state.Pid}). " +
                         $"Устройство активно для ввода (~0.5-1.5с); для жёсткой блокировки требуется USBGuard/authorized=0.");
        }
    }

    private void RaiseAlert(string severity, string ruleCode, DeviceState state, string message)
    {
        if (!state.FiredAlertRules.Add(ruleCode))
            return; // Дедупликация алертов на одно физическое устройство

        _store.SaveAlert(severity, ruleCode, state, message);

        Console.ForegroundColor = severity switch
        {
            "CRITICAL" => ConsoleColor.Red,
            "HIGH" => ConsoleColor.DarkYellow,
            "MEDIUM" => ConsoleColor.Yellow,
            _ => ConsoleColor.Cyan
        };
        Console.WriteLine($"  [!!! ALERT/{severity}] [{ruleCode}] {message}");
        Console.ResetColor();
    }

    /// <summary>
    /// Извлекает путь физического USB-устройства из любого DEVPATH (включая /block/sda1, /input/event12, :1.0).
    /// Пример: /devices/.../usb1/1-2/1-2:1.0/host6/.../sda1 -> /devices/.../usb1/1-2
    /// </summary>
    private static string? ExtractPhysicalUsbDevPath(string devPath, out string sysName)
    {
        sysName = "";
        var parts = devPath.Split('/', StringSplitOptions.RemoveEmptyEntries);

        int usbRootIdx = -1;
        for (int i = 0; i < parts.Length; i++)
        {
            if (UsbRootSegment.IsMatch(parts[i]))
            {
                usbRootIdx = i;
                break;
            }
        }

        if (usbRootIdx == -1) return null; // Не USB-шина (PCIe, виртуальные устройства, PS/2 и т.д.)

        int lastPhysicalIdx = -1;
        for (int i = usbRootIdx + 1; i < parts.Length; i++)
        {
            if (UsbDeviceSegment.IsMatch(parts[i]))
            {
                lastPhysicalIdx = i;
            }
            else
            {
                break; // Дошли до интерфейса (1-2:1.0) или дочерней подсистемы
            }
        }

        if (lastPhysicalIdx == -1) return null; // Это сам root-хаб usb1

        sysName = parts[lastPhysicalIdx];
        return "/" + string.Join('/', parts[..(lastPhysicalIdx + 1)]);
    }
}

#endregion

#region 4. Локальное персистентное хранилище (SQLite)

internal sealed class SqliteEventStore : IDisposable
{
    private readonly SqliteConnection _conn;
    private readonly object _sync = new();

    public SqliteEventStore(string dbPath)
    {
        _conn = new SqliteConnection($"Data Source={dbPath}");
        _conn.Open();
        InitSchema();
    }

    private void InitSchema()
    {
        using var cmd = _conn.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS device_events (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp_utc TEXT NOT NULL,
                event_type    TEXT NOT NULL,
                port_path     TEXT NOT NULL,
                sys_name      TEXT NOT NULL,
                id_path       TEXT,
                vid           TEXT NOT NULL,
                pid           TEXT NOT NULL,
                serial        TEXT,
                vendor_name   TEXT,
                model_name    TEXT,
                classes_raw   TEXT,
                classes_human TEXT,
                fs_info       TEXT,
                net_interface TEXT,
                max_power     TEXT,
                dev_node      TEXT
            );

            CREATE TABLE IF NOT EXISTS security_alerts (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp_utc TEXT NOT NULL,
                severity      TEXT NOT NULL,
                rule_code     TEXT NOT NULL,
                port_path     TEXT NOT NULL,
                vid           TEXT NOT NULL,
                pid           TEXT NOT NULL,
                message       TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_events_port ON device_events(port_path, timestamp_utc);
            CREATE INDEX IF NOT EXISTS idx_alerts_time ON security_alerts(timestamp_utc);
            """;
        cmd.ExecuteNonQuery();
    }

    public void SaveDeviceEvent(string eventType, DeviceState s, string? devNode)
    {
        lock (_sync)
        {
            using var cmd = _conn.CreateCommand();
            cmd.CommandText = """
                INSERT INTO device_events (
                    timestamp_utc, event_type, port_path, sys_name, id_path,
                    vid, pid, serial, vendor_name, model_name,
                    classes_raw, classes_human, fs_info, net_interface, max_power, dev_node
                ) VALUES (
                    $ts, $type, $port, $sys, $idpath,
                    $vid, $pid, $sn, $vendor, $model,
                    $craw, $chum, $fs, $net, $pwr, $node
                );
                """;
            cmd.Parameters.AddWithValue("$ts", DateTime.UtcNow.ToString("O"));
            cmd.Parameters.AddWithValue("$type", eventType);
            cmd.Parameters.AddWithValue("$port", s.PhysicalPortPath);
            cmd.Parameters.AddWithValue("$sys", s.SysName);
            cmd.Parameters.AddWithValue("$idpath", s.IdPath);
            cmd.Parameters.AddWithValue("$vid", s.Vid);
            cmd.Parameters.AddWithValue("$pid", s.Pid);
            cmd.Parameters.AddWithValue("$sn", s.Serial);
            cmd.Parameters.AddWithValue("$vendor", s.VendorName);
            cmd.Parameters.AddWithValue("$model", s.ModelName);
            cmd.Parameters.AddWithValue("$craw", s.FormatRawInterfaces());
            cmd.Parameters.AddWithValue("$chum", s.FormatClasses());
            cmd.Parameters.AddWithValue("$fs", (object?)s.FilesystemInfo ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$net", (object?)s.NetworkInterface ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$pwr", s.MaxPower);
            cmd.Parameters.AddWithValue("$node", (object?)devNode ?? DBNull.Value);
            cmd.ExecuteNonQuery();
        }
    }

    public void SaveAlert(string severity, string ruleCode, DeviceState s, string message)
    {
        lock (_sync)
        {
            using var cmd = _conn.CreateCommand();
            cmd.CommandText = """
                INSERT INTO security_alerts (
                    timestamp_utc, severity, rule_code, port_path, vid, pid, message
                ) VALUES ($ts, $sev, $code, $port, $vid, $pid, $msg);
                """;
            cmd.Parameters.AddWithValue("$ts", DateTime.UtcNow.ToString("O"));
            cmd.Parameters.AddWithValue("$sev", severity);
            cmd.Parameters.AddWithValue("$code", ruleCode);
            cmd.Parameters.AddWithValue("$port", s.PhysicalPortPath);
            cmd.Parameters.AddWithValue("$vid", s.Vid);
            cmd.Parameters.AddWithValue("$pid", s.Pid);
            cmd.Parameters.AddWithValue("$msg", message);
            cmd.ExecuteNonQuery();
        }
    }

    public void Dispose() => _conn.Dispose();
}

#endregion