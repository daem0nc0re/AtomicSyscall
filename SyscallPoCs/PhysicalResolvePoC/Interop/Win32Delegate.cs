using System;
using System.Runtime.InteropServices;

namespace PhysicalResolvePoC.Interop
{
    class Win32Delegate
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int NtQuerySystemInformation(
            Win32Const.SYSTEM_INFORMATION_CLASS SystemInformationClass,
            IntPtr SystemInformation,
            int SystemInformationLength,
            ref int ReturnLength);
    }
}
