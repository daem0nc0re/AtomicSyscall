using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using InitialProcessResolver.Interop;

namespace InitialProcessResolver.Library
{
    using NTSTATUS = Int32;

    internal class Helpers
    {
        public static IntPtr GetNtdllBaseAddress()
        {
            var pNtdll = IntPtr.Zero;

            foreach (ProcessModule module in Process.GetCurrentProcess().Modules)
            {
                if (string.Compare(module.ModuleName, "ntdll.dll", true) == 0)
                {
                    pNtdll = module.BaseAddress;
                    break;
                }
            }

            return pNtdll;
        }


        public static bool GetProcessBasicInformation(
            IntPtr hProcess,
            out PROCESS_BASIC_INFORMATION pbi)
        {
            NTSTATUS ntstatus;
            bool status;
            var nSizeBuffer = Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION));
            IntPtr pInfoBuffer = Marshal.AllocHGlobal(nSizeBuffer);

            ntstatus = NativeMethods.NtQueryInformationProcess(
                hProcess,
                PROCESSINFOCLASS.ProcessBasicInformation,
                pInfoBuffer,
                (uint)nSizeBuffer,
                out uint _);
            status = (ntstatus == Win32Consts.STATUS_SUCCESS);

            if (status)
            {
                pbi = (PROCESS_BASIC_INFORMATION)Marshal.PtrToStructure(
                    pInfoBuffer,
                    typeof(PROCESS_BASIC_INFORMATION));
            }
            else
            {
                pbi = new PROCESS_BASIC_INFORMATION();
            }

            Marshal.FreeHGlobal(pInfoBuffer);

            return status;
        }


        public static IntPtr[] SearchBytes(IntPtr pBaseBuffer, int nRange, byte[] searchBytes)
        {
            var results = new List<IntPtr>();

            for (var count = 0; count < (nRange - searchBytes.Length); count++)
            {
                var found = false;

                for (var position = 0; position < searchBytes.Length; position++)
                {
                    found = (Marshal.ReadByte(pBaseBuffer, count + position) == searchBytes[position]);

                    if (!found)
                        break;
                }

                if (found)
                {
                    if (Environment.Is64BitProcess)
                        results.Add(new IntPtr(pBaseBuffer.ToInt64() + count));
                    else
                        results.Add(new IntPtr(pBaseBuffer.ToInt32() + count));
                }
            }

            return results.ToArray();
        }
    }
}
