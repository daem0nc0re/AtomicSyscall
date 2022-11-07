using System;
using System.Runtime.InteropServices;
using System.Text;

namespace HeavensGatePoC.Interop
{
    using NTSTATUS = Int32;

    internal class NativeMethods
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool FileTimeToSystemTime(
            in LARGE_INTEGER lpFileTime,
            out SYSTEMTIME lpSystemTime);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern int FormatMessage(
            FormatMessageFlags dwFlags,
            IntPtr lpSource,
            int dwMessageId,
            int dwLanguageId,
            StringBuilder lpBuffer,
            int nSize,
            IntPtr Arguments);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SystemTimeToTzSpecificLocalTime(
            in TIME_ZONE_INFORMATION lpTimeZoneInformation,
            in SYSTEMTIME lpUniversalTime,
            out SYSTEMTIME lpLocalTime);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SystemTimeToTzSpecificLocalTime(
            IntPtr lpTimeZoneInformation,
            in SYSTEMTIME lpUniversalTime,
            out SYSTEMTIME lpLocalTime);
    }
}
