using System;
using System.Runtime.InteropServices;

namespace HeavensGatePoC.Interop
{
    using NTSTATUS = Int32;

    [StructLayout(LayoutKind.Sequential)]
    internal struct LDR_DATA_TABLE_ENTRY64_PARTIAL
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
    internal struct UNICODE_STRING64
    {
        public ushort Length;
        public ushort MaximumLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] Padding0;
        public ulong Buffer;
    }
}
