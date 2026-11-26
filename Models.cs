namespace ArmDeviceAgent;

public sealed class AgentOptions
{
    public string BackendBatchUrl { get; set; } = "https://localhost:5001/api/v1/events/batch";
    public string ApiKey { get; set; } = string.Empty;
    public int BatchWindowSeconds { get; set; } = 3;
    public int MaxBatchSize { get; set; } = 50;
    public string SqliteDbPath { get; set; } = "agent_events_queue.db";
}

public sealed record DeviceProperties(
    string InstanceId,
    string Vid,
    string Pid,
    string Serial,
    bool IsPortGeneratedSerial,
    string[] CompatibleIds,
    string[] ResolvedClasses,
    Guid ContainerId,
    string PrimaryLocationPath
);

public sealed record RawPnpEvent(
    DateTimeOffset Timestamp,
    string Action,        // "DEVICE_CONNECTED" | "DEVICE_DISCONNECTED" | "INITIAL_INVENTORY"
    string TriggerSource, // "hotplug" | "boot_inventory" | "wake_from_sleep"
    DeviceProperties Device
);

public sealed record DriveAttachment(
    string DriveLetter,
    string VolumeLabel,
    string FileSystem
);

public sealed record AggregatedDeviceEvent(
    Guid EventId,
    DateTimeOffset Timestamp,
    string Action,
    string TriggerSource,
    Guid ContainerId,
    string Vid,
    string Pid,
    string Serial,
    bool IsPortGeneratedSerial,
    string LocationPath,
    string[] InstanceIds,
    string[] CompatibleIds,
    string[] DeviceClasses,
    DriveAttachment[] MountedDrives,
    bool IsComposite,
    bool IsReenumeration,
    string? PreviousDeviceSignature
);

public sealed record EventBatchPayload(
    Guid BatchId,
    string HostName,
    string ActiveUser,
    DateTimeOffset SentAt,
    List<AggregatedDeviceEvent> Events
);