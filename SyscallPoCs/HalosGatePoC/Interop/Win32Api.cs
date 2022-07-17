using System;
using System.Runtime.InteropServices;
using System.Text;

namespace HalosGatePoC.Interop
{
    class Win32Api
    {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern int FormatMessage(
            Win32Const.FormatMessageFlags dwFlags,
            IntPtr lpSource,
            int dwMessageId,
            int dwLanguageId,
            StringBuilder lpBuffer,
            int nSize,
            IntPtr Arguments);
    }
}
