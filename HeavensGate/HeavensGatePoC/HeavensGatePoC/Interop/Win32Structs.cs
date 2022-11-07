using System;
using System.Runtime.InteropServices;

namespace HeavensGatePoC.Interop
{
    using NTSTATUS = Int32;

    [StructLayout(LayoutKind.Sequential)]
    internal struct CURDIR64
    {
        public UNICODE_STRING64 DosPath;
        public ulong Handle;
    }

    [StructLayout(LayoutKind.Explicit)]
    internal struct LARGE_INTEGER
    {
        [FieldOffset(0)]
        public int Low;
        [FieldOffset(4)]
        public int High;
        [FieldOffset(0)]
        public long QuadPart;

        public long ToInt64()
        {
            return ((long)this.High << 32) | (uint)this.Low;
        }

        public static LARGE_INTEGER FromInt64(long value)
        {
            return new LARGE_INTEGER
            {
                Low = (int)(value),
                High = (int)((value >> 32))
            };
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LDR_DATA_TABLE_ENTRY64
    {
        public LIST_ENTRY64 InLoadOrderLinks;
        public LIST_ENTRY64 InMemoryOrderLinks;
        public LIST_ENTRY64 InInitializationOrderLinks;
        public ulong DllBase;
        public ulong EntryPoint;
        public uint SizeOfImage;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] Padding0;
        public UNICODE_STRING64 FullDllName;
        public UNICODE_STRING64 BaseDllName;
        public uint Flags;
        public ushort ObsoleteLoadCount;
        public ushort TlsIndex;
        public LIST_ENTRY64 HashLinks;
        public uint TimeDateStamp;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] Padding1;
        public ulong  /* _ACTIVATION_CONTEXT* */ EntryPointActivationContext;
        public ulong Lock;
        public ulong /* _LDR_DDAG_NODE* */ DdagNode;
        public LIST_ENTRY64 NodeModuleLink;
        public ulong  /* _LDRP_LOAD_CONTEXT* */ LoadContext;
        public ulong ParentDllBase;
        public ulong SwitchBackContext;
        public RTL_BALANCED_NODE64 BaseAddressIndexNode;
        public RTL_BALANCED_NODE64 MappingInfoIndexNode;
        public ulong OriginalBase;
        public LARGE_INTEGER LoadTime;
        public uint BaseNameHashValue;
        public LDR_DLL_LOAD_REASON LoadReason;
        public uint ImplicitPathOptions;
        public uint ReferenceCount;
        public uint DependentLoadFlags;
        public byte SigningLevel;
        public uint CheckSum;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] Padding2;
        public ulong ActivePatchImageBase;
        public LDR_HOT_PATCH_STATE HotPatchState;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] Padding3;
    }


    [StructLayout(LayoutKind.Sequential)]
    internal struct LIST_ENTRY64
    {
        public ulong Flink;
        public ulong Blink;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PEB_LDR_DATA64
    {
        public uint Length;
        public BOOLEAN Initialized;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
        public byte[] Padding0;
        public ulong SsHandle;
        public LIST_ENTRY64 InLoadOrderModuleList;
        public LIST_ENTRY64 InMemoryOrderModuleList;
        public LIST_ENTRY64 InInitializationOrderModuleList;
        public ulong EntryInProgress;
        public BOOLEAN ShutdownInProgress;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 7)]
        public byte[] Padding1;
        public ulong ShutdownThreadId;
    }


    [StructLayout(LayoutKind.Sequential)]
    internal struct PEB64_PARTIAL
    {
        public BOOLEAN InheritedAddressSpace;
        public BOOLEAN ReadImageFileExecOptions;
        public BOOLEAN BeingDebugged;
        public byte BitField;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] Padding0;
        public ulong Mutant;
        public ulong ImageBaseAddress;
        public ulong Ldr; // _PEB_LDR_DATA*
        public ulong ProcessParameters; // _RTL_USER_PROCESS_PARAMETERS*
        public ulong SubSystemData;
        public ulong ProcessHeap;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_BASIC_INFORMATION64
    {
        public NTSTATUS ExitStatus;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] Padding0;
        public long PebBaseAddress;
        public long AffinityMask;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] Padding1;
        public int BasePriority;
        public long UniqueProcessId;
        public long InheritedFromUniqueProcessId;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct RTL_BALANCED_NODE64
    {
        public ulong /* RTL_BALANCED_NODE* */ Left;
        public ulong /* RTL_BALANCED_NODE* */ Right;
        public ulong ParentValue;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct RTL_DRIVE_LETTER_CURDIR64
    {
        public ushort Flags;
        public ushort Length;
        public uint TimeStamp;
        public STRING64 DosPath;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct RTL_USER_PROCESS_PARAMETERS64
    {
        public uint MaximumLength;
        public uint Length;
        public uint Flags;
        public uint DebugFlags;
        public ulong ConsoleHandle;
        public uint ConsoleFlags;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] Padding0;
        public ulong StandardInput;
        public ulong StandardOutput;
        public ulong StandardError;
        public CURDIR64 CurrentDirectory;
        public UNICODE_STRING64 DllPath;
        public UNICODE_STRING64 ImagePathName;
        public UNICODE_STRING64 CommandLine;
        public ulong Environment;
        public uint StartingX;
        public uint StartingY;
        public uint CountX;
        public uint CountY;
        public uint CountCharsX;
        public uint CountCharsY;
        public uint FillAttribute;
        public uint WindowFlags;
        public uint ShowWindowFlags;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] Padding1;
        public UNICODE_STRING64 WindowTitle;
        public UNICODE_STRING64 DesktopInfo;
        public UNICODE_STRING64 ShellInfo;
        public UNICODE_STRING64 RuntimeData;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public RTL_DRIVE_LETTER_CURDIR64[] CurrentDirectores;
        public ulong EnvironmentSize;
        public ulong EnvironmentVersion;
        public ulong PackageDependencyData;
        public uint ProcessGroupId;
        public uint LoaderThreads;
        public UNICODE_STRING64 RedirectionDllName;
        public UNICODE_STRING64 HeapPartitionName;
        public ulong DefaultThreadpoolCpuSetMasks;
        public uint DefaultThreadpoolCpuSetMaskCount;
        public uint DefaultThreadpoolThreadMaximum;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct STRING64
    {
        public ushort Length;
        public ushort MaximumLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] Padding0;
        public ulong Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEMTIME
    {
        public short wYear;
        public short wMonth;
        public DAY_OF_WEEK wDayOfWeek;
        public short wDay;
        public short wHour;
        public short wMinute;
        public short wSecond;
        public short wMilliseconds;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TIME_ZONE_INFORMATION
    {
        public int Bias;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public short[] StandardName;
        public SYSTEMTIME StandardDate;
        public int StandardBias;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public short[] DaylightName;
        public SYSTEMTIME DaylightDate;
        public int DaylightBias;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct UNICODE_STRING64
    {
        public ushort Length;
        public ushort MaximumLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] Padding0;
        public ulong Buffer;
    }
}
