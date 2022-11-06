using System;
using System.Runtime.InteropServices;

namespace HeavensGatePoC.Interop
{
    using NTSTATUS = Int32;

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_BASIC_INFORMATION
    {
        public NTSTATUS ExitStatus;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        private readonly byte[] Padding0;
        public long PebBaseAddress;
        public long AffinityMask;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        private readonly byte[] Padding1;
        public int BasePriority;
        public long UniqueProcessId;
        public long InheritedFromUniqueProcessId;
    }
}
