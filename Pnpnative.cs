using System.Runtime.InteropServices;
using System.Text;

namespace ArmDeviceAgent;

internal static class PnpNative
{
    public const uint DIGCF_PRESENT = 0x00000002;
    public const uint DIGCF_ALLCLASSES = 0x00000004;

    public const uint CM_NOTIFY_FILTER_FLAG_ALL_DEVICE_INSTANCES = 0x00000002;
    public const uint CM_NOTIFY_FILTER_TYPE_DEVICEINSTANCE = 2;

    public const uint CM_NOTIFY_ACTION_DEVICEINSTANCEENUMERATED = 7;
    public const uint CM_NOTIFY_ACTION_DEVICEINSTANCESTARTED = 8;
    public const uint CM_NOTIFY_ACTION_DEVICEINSTANCEREMOVED = 9;

    public const uint DEVICE_NOTIFY_CALLBACK = 2;
    public const uint PBT_APMRESUMESUSPEND = 7;
    public const uint PBT_APMRESUMEAUTOMATIC = 18;

    public static readonly DEVPROPKEY DEVPKEY_Device_CompatibleIds =
        new(new Guid("a45c254e-df1c-4efd-8020-67d146a850e0"), 4);

    public static readonly DEVPROPKEY DEVPKEY_Device_LocationInfo =
        new(new Guid("a45c254e-df1c-4efd-8020-67d146a850e0"), 15);

    public static readonly DEVPROPKEY DEVPKEY_Device_LocationPaths =
        new(new Guid("a45c254e-df1c-4efd-8020-67d146a850e0"), 37);

    public static readonly DEVPROPKEY DEVPKEY_Device_ContainerId =
        new(new Guid("8c7ed206-3f8a-4827-b3ab-ae9e1fae6c6a"), 2);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate uint PCM_NOTIFY_CALLBACK(
        IntPtr hNotify,
        IntPtr Context,
        uint Action,
        IntPtr EventData,
        uint EventDataSize);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate uint DeviceNotifyCallbackRoutine(
        IntPtr Context,
        uint Type,
        IntPtr Setting);

    [StructLayout(LayoutKind.Sequential)]
    public struct DEVPROPKEY(Guid fmtid, uint pid)
    {
        public Guid fmtid = fmtid;
        public uint pid = pid;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SP_DEVINFO_DATA
    {
        public uint cbSize;
        public Guid ClassGuid;
        public uint DevInst;
        public IntPtr Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CM_NOTIFY_FILTER
    {
        public uint cbSize;
        public uint Flags;
        public uint FilterType;
        public uint Reserved;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 400)]
        public byte[] UnionBuffer;

        public static CM_NOTIFY_FILTER CreateAllDeviceInstances() => new()
        {
            cbSize = (uint)Marshal.SizeOf<CM_NOTIFY_FILTER>(),
            Flags = CM_NOTIFY_FILTER_FLAG_ALL_DEVICE_INSTANCES,
            FilterType = CM_NOTIFY_FILTER_TYPE_DEVICEINSTANCE,
            Reserved = 0,
            UnionBuffer = new byte[400]
        };
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS
    {
        public DeviceNotifyCallbackRoutine Callback;
        public IntPtr Context;
    }

    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
    public static extern uint CM_Register_Notification(
        ref CM_NOTIFY_FILTER pFilter,
        IntPtr pContext,
        PCM_NOTIFY_CALLBACK pCallback,
        out IntPtr pNotifyContext);

    [DllImport("cfgmgr32.dll")]
    public static extern uint CM_Unregister_Notification(IntPtr NotifyContext);

    [DllImport("powrprof.dll")]
    public static extern uint PowerRegisterSuspendResumeNotification(
        uint Flags,
        ref DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS Recipient,
        out IntPtr RegistrationHandle);

    [DllImport("powrprof.dll")]
    public static extern uint PowerUnregisterSuspendResumeNotification(IntPtr RegistrationHandle);

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr SetupDiGetClassDevsW(
        IntPtr ClassGuid,
        string? Enumerator,
        IntPtr hwndParent,
        uint Flags);

    [DllImport("setupapi.dll", SetLastError = true)]
    public static extern IntPtr SetupDiCreateDeviceInfoList(IntPtr ClassGuid, IntPtr hwndParent);

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool SetupDiOpenDeviceInfoW(
        IntPtr DeviceInfoSet,
        string DeviceInstanceId,
        IntPtr hwndParent,
        uint OpenFlags,
        ref SP_DEVINFO_DATA DeviceInfoData);

    [DllImport("setupapi.dll", SetLastError = true)]
    public static extern bool SetupDiEnumDeviceInfo(
        IntPtr DeviceInfoSet,
        uint MemberIndex,
        ref SP_DEVINFO_DATA DeviceInfoData);

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool SetupDiGetDeviceInstanceIdW(
        IntPtr DeviceInfoSet,
        ref SP_DEVINFO_DATA DeviceInfoData,
        StringBuilder DeviceInstanceId,
        int DeviceInstanceIdSize,
        out int RequiredSize);

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool SetupDiGetDevicePropertyW(
        IntPtr DeviceInfoSet,
        ref SP_DEVINFO_DATA DeviceInfoData,
        ref DEVPROPKEY PropertyKey,
        out uint PropertyType,
        byte[]? PropertyBuffer,
        uint PropertyBufferSize,
        out uint RequiredSize,
        uint Flags);

    [DllImport("setupapi.dll", SetLastError = true)]
    public static extern bool SetupDiDestroyDeviceInfoList(IntPtr DeviceInfoSet);

    public static string[] ReadStringListProperty(IntPtr devInfoSet, ref SP_DEVINFO_DATA devInfoData, DEVPROPKEY key)
    {
        SetupDiGetDevicePropertyW(devInfoSet, ref devInfoData, ref key, out _, null, 0, out uint reqSize, 0);
        if (reqSize == 0) return Array.Empty<string>();

        byte[] buffer = new byte[reqSize];
        if (!SetupDiGetDevicePropertyW(devInfoSet, ref devInfoData, ref key, out _, buffer, reqSize, out _, 0))
            return Array.Empty<string>();

        return Encoding.Unicode.GetString(buffer)
            .Split('\0', StringSplitOptions.RemoveEmptyEntries);
    }

    public static Guid ReadGuidProperty(IntPtr devInfoSet, ref SP_DEVINFO_DATA devInfoData, DEVPROPKEY key)
    {
        byte[] buffer = new byte[16];
        if (SetupDiGetDevicePropertyW(devInfoSet, ref devInfoData, ref key, out _, buffer, 16, out _, 0))
            return new Guid(buffer);
        return Guid.Empty;
    }
}