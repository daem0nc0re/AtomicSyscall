using System;
using System.Runtime.InteropServices;
using System.Text;
using HellsGatePoC.Interop;

namespace HellsGatePoC.Library
{
    class Helpers
    {
        public static string GetWin32StatusMessage(int code, bool isNtStatus)
        {
            var message = new StringBuilder();
            var messageSize = 255;
            Win32Const.FormatMessageFlags messageFlag;
            IntPtr pNtdll;
            message.Capacity = messageSize;

            if (isNtStatus)
            {
                pNtdll = Win32Api.LoadLibrary("ntdll.dll");
                messageFlag = Win32Const.FormatMessageFlags.FORMAT_MESSAGE_FROM_HMODULE |
                    Win32Const.FormatMessageFlags.FORMAT_MESSAGE_FROM_SYSTEM;
            }
            else
            {
                pNtdll = IntPtr.Zero;
                messageFlag = Win32Const.FormatMessageFlags.FORMAT_MESSAGE_FROM_SYSTEM;
            }

            int ret = Win32Api.FormatMessage(
                messageFlag,
                pNtdll,
                code,
                0,
                message,
                messageSize,
                IntPtr.Zero);

            if (isNtStatus)
                Win32Api.FreeLibrary(pNtdll);

            if (ret == 0)
            {
                return string.Format("[STATUS] Code 0x{0}", code.ToString("X8"));
            }
            else
            {
                return string.Format(
                    "[STATUS] Code 0x{0} : {1}",
                    code.ToString("X8"),
                    message.ToString().Trim());
            }
        }

        public static void ZeroMemory(IntPtr buffer, int size)
        {
            var nullBytes = new byte[size];
            Marshal.Copy(nullBytes, 0, buffer, size);
        }
    }
}
