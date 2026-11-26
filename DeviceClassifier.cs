using System.Management;
using System.Text.RegularExpressions;

namespace ArmDeviceAgent;

public static partial class DeviceClassifier
{
    [GeneratedRegex(@"VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})", RegexOptions.Compiled)]
    private static partial Regex VidPidRegex();

    [GeneratedRegex(@"#USBMI\(\d+\)$", RegexOptions.IgnoreCase | RegexOptions.Compiled)]
    private static partial Regex UsbMiSuffixRegex();

    [GeneratedRegex(@"USB\((\d+)\)", RegexOptions.IgnoreCase | RegexOptions.Compiled)]
    private static partial Regex UsbPortRegex();

    public static DeviceProperties BuildProperties(
        string instanceId,
        string[] compatibleIds,
        Guid containerId,
        string[] locationPaths,
        string[] locationInfo)
    {
        var match = VidPidRegex().Match(instanceId);
        string vid = match.Success ? match.Groups[1].Value.ToUpperInvariant() : "0000";
        string pid = match.Success ? match.Groups[2].Value.ToUpperInvariant() : "0000";

        string[] parts = instanceId.Split('\\');
        string serial = parts.Length >= 3 ? parts[2] : string.Empty;
        bool isPortGenerated = serial.Contains('&');

        string primaryLocation = locationPaths.FirstOrDefault()
            ?? locationInfo.FirstOrDefault()
            ?? "UNKNOWN_PORT";

        if (instanceId.Contains("ROOT_HUB", StringComparison.OrdinalIgnoreCase))
        {
            return new DeviceProperties(
                InstanceId: instanceId,
                Vid: vid,
                Pid: pid,
                Serial: serial,
                IsPortGeneratedSerial: isPortGenerated,
                CompatibleIds: compatibleIds,
                ResolvedClasses: ["RootHub"],
                ContainerId: containerId,
                PrimaryLocationPath: primaryLocation
            );
        }

        string[] classes = compatibleIds
            .Select(MapCompatibleIdToClass)
            .Where(c => c != "CompositeParent")
            .Distinct()
            .ToArray();

        if (classes.Length == 0)
            classes = ["Unknown"];

        return new DeviceProperties(
            InstanceId: instanceId,
            Vid: vid,
            Pid: pid,
            Serial: serial,
            IsPortGeneratedSerial: isPortGenerated,
            CompatibleIds: compatibleIds,
            ResolvedClasses: classes,
            ContainerId: containerId,
            PrimaryLocationPath: primaryLocation
        );
    }

    public static string GetBasePhysicalLocation(string locationPath)
    {
        if (string.IsNullOrWhiteSpace(locationPath) || locationPath == "UNKNOWN_PORT")
            return "UNKNOWN_PORT";

        return UsbMiSuffixRegex().Replace(locationPath, string.Empty);
    }

    public static string FormatShortPort(string locationPath)
    {
        if (string.IsNullOrWhiteSpace(locationPath) || locationPath == "UNKNOWN_PORT")
            return "неизвестный порт";

        var matches = UsbPortRegex().Matches(locationPath);
        if (matches.Count == 0)
            return locationPath;

        var ports = matches.Select(m => m.Groups[1].Value);
        return "USB " + string.Join(" -> ", ports);
    }

    public static string MapCompatibleIdToClass(string compatId)
    {
        string upper = compatId.ToUpperInvariant();

        if (upper.Contains("DEVCLASS_00") || upper.Contains("CLASS_00")) return "CompositeParent";
        if (upper.Contains("USB20_HUB") || upper.Contains("USB30_HUB") || upper.Contains("CLASS_09"))
            return "Hub";
        if (upper.Contains("CLASS_08")) return "MassStorage";
        if (upper.Contains("CLASS_03")) return "HID";
        if (upper.Contains("CLASS_02") || upper.Contains("CLASS_EF&SUBCLASS_04") || upper.Contains("PROT_03"))
            return "Network_CDC_RNDIS";
        if (upper.Contains("CLASS_06")) return "MTP_PTP";
        if (upper.Contains("CLASS_0B")) return "SmartCard_CCID";
        if (upper.Contains("CLASS_01")) return "Audio";
        if (upper.Contains("CLASS_0E")) return "Video";
        if (upper.Contains("CLASS_07")) return "Printer";
        if (upper.Contains("CLASS_0A")) return "CDC_Data";
        if (upper.Contains("CLASS_E0")) return "Wireless";
        if (upper.Contains("CLASS_FF")) return "VendorSpecific";

        return "Unknown";
    }

    public static string FormatClassesRu(string[] classes)
    {
        var readable = classes
            .Where(c => c != "Unknown" && c != "CompositeParent")
            .Select(c => c switch
            {
                "MassStorage" => "Флешка / Внешний диск",
                "HID" => "Устройство ввода (клавиатура/мышь)",
                "Network_CDC_RNDIS" => "USB-модем / Сетевой адаптер",
                "MTP_PTP" => "Смартфон / Камера (MTP/PTP)",
                "SmartCard_CCID" => "Ридер смарт-карт / Токен",
                "Audio" => "Аудиоустройство (гарнитура/звуковая карта)",
                "Video" => "Веб-камера / Видеоустройство",
                "Hub" => "USB-хаб",
                "Printer" => "Принтер",
                "CDC_Data" => "COM-порт / Последовательный интерфейс",
                "Wireless" => "Беспроводной адаптер (Bluetooth/Wi-Fi)",
                "VendorSpecific" => "Спецустройство (Vendor-Specific)",
                _ => c
            })
            .Distinct()
            .ToArray();

        return readable.Length > 0 ? string.Join(" + ", readable) : "Неизвестное USB-устройство";
    }

    public static async Task<DriveAttachment[]> FindMountedUsbDrivesWithRetryAsync(
        string vid,
        string pid,
        string serial,
        CancellationToken ct)
    {
        var drives = FindMountedUsbDrives(vid, pid, serial);
        if (drives.Length > 0)
            return drives;

        // Даём Windows 1.5 сек на завершение монтирования файловой системы
        await Task.Delay(1500, ct);
        return FindMountedUsbDrives(vid, pid, serial);
    }

    public static DriveAttachment[] FindMountedUsbDrives(string vid, string pid, string serial)
    {
        var attachments = new List<DriveAttachment>();
        try
        {
            using var diskSearcher = new ManagementObjectSearcher(
                "SELECT DeviceID, PNPDeviceID FROM Win32_DiskDrive WHERE InterfaceType='USB'");

            foreach (ManagementObject disk in diskSearcher.Get())
            {
                string pnpId = disk["PNPDeviceID"]?.ToString() ?? string.Empty;
                bool matches = (!string.IsNullOrEmpty(serial) && !serial.Contains('&') &&
                                pnpId.Contains(serial, StringComparison.OrdinalIgnoreCase))
                               || (pnpId.Contains(vid, StringComparison.OrdinalIgnoreCase) &&
                                   pnpId.Contains(pid, StringComparison.OrdinalIgnoreCase));

                if (!matches) continue;

                string diskId = disk["DeviceID"]?.ToString()?.Replace("\\", "\\\\") ?? string.Empty;
                using var partSearcher = new ManagementObjectSearcher(
                    $"ASSOCIATORS OF {{Win32_DiskDrive.DeviceID='{diskId}'}} WHERE AssocClass = Win32_DiskDriveToDiskPartition");

                foreach (ManagementObject partition in partSearcher.Get())
                {
                    string partId = partition["DeviceID"]?.ToString() ?? string.Empty;
                    using var logicalSearcher = new ManagementObjectSearcher(
                        $"ASSOCIATORS OF {{Win32_DiskPartition.DeviceID='{partId}'}} WHERE AssocClass = Win32_LogicalDiskToPartition");

                    foreach (ManagementObject logical in logicalSearcher.Get())
                    {
                        string letter = logical["DeviceID"]?.ToString() ?? string.Empty;
                        if (!string.IsNullOrEmpty(letter))
                        {
                            attachments.Add(new DriveAttachment(
                                DriveLetter: letter + "\\",
                                VolumeLabel: logical["VolumeName"]?.ToString() ?? string.Empty,
                                FileSystem: logical["FileSystem"]?.ToString() ?? string.Empty
                            ));
                        }
                    }
                }
            }
        }
        catch
        {
            // Игнорируем гонку при резком извлечении тома
        }

        return attachments.ToArray();
    }

    public static string GetLoggedOnUser()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT UserName FROM Win32_ComputerSystem");
            foreach (ManagementObject obj in searcher.Get())
            {
                string? user = obj["UserName"]?.ToString();
                if (!string.IsNullOrWhiteSpace(user)) return user;
            }
        }
        catch { }

        return "SYSTEM / LOCKED";
    }
}
