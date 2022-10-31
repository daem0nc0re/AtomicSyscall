using System;
using System.Runtime.InteropServices;
using System.Text;

namespace HeavensGatePoC.Interop
{
    using NTSTATUS = Int32;

    internal class NativeMethods
    {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern int FormatMessage(
            FormatMessageFlags dwFlags,
            IntPtr lpSource,
            int dwMessageId,
            int dwLanguageId,
            StringBuilder lpBuffer,
            int nSize,
            IntPtr Arguments);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate NTSTATUS NtQueryInformationProcess(
            IntPtr ProcessHandle,
            PROCESS_INFORMATION_CLASS ProcessInformationClass,
            IntPtr ProcessInformation,
            uint ProcessInformationLength,
            IntPtr pReturnLength);
    }
}
