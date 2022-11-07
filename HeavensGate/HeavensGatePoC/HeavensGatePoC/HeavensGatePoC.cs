using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using HeavensGatePoC.Interop;
using HeavensGatePoC.Library;

namespace HeavensGatePoC
{
    using NTSTATUS = Int32;

    internal class HeavensGatePoC
    {
        static void Main()
        {
            string architecture = Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE");

            if (!Environment.Is64BitOperatingSystem || !Helpers.CompareStringIgnoreCase(architecture, "x86"))
            {
                Console.WriteLine("\n[!] Should be run in AMD64.\n");

                return;
            }

            if (Environment.Is64BitProcess || !Environment.Is64BitOperatingSystem)
            {
                Console.WriteLine("\n[!] Should be built as 32bit binary and run in 64bit OS.\n");

                return;
            }

            /*
             * Enumerate Drivers
             */
            NTSTATUS ntstatus;
            IntPtr pSystemInfo;
            ulong pPeb64;
            Dictionary<string, ulong> x64ModuleLists;
            PROCESS_BASIC_INFORMATION64 pbi;
            int nBufferSize = Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION64));

            pPeb64 = Utilities.GetPeb64();
            x64ModuleLists = Utilities.Get64BitModuleEntries();

            Console.WriteLine("[*] ntdll!_PEB64 @ 0x{0}", pPeb64.ToString("X16"));
            Console.WriteLine("[+] Got 64bit modules.");
            foreach (var mod in x64ModuleLists)
                Console.WriteLine("    [*] 0x{0} : {1}", mod.Value.ToString("X16"), mod.Key);

            Console.WriteLine("[>] Trying to get current process information.");

            pSystemInfo = Marshal.AllocHGlobal(nBufferSize);
            Helpers.ZeroMemory(pSystemInfo, nBufferSize);

            ntstatus = Syscall.NtQueryInformationProcess(
                Process.GetCurrentProcess().Handle,
                PROCESS_INFORMATION_CLASS.ProcessBasicInformation,
                pSystemInfo,
                (uint)nBufferSize,
                out uint NumberOfBytes);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                Console.WriteLine("[-] Failed to get current process basic information.");
                Console.WriteLine("    [*] NTSTATUS : 0x{0}", ntstatus.ToString("X8"));
            }
            else
            {
                pbi = (PROCESS_BASIC_INFORMATION64)Marshal.PtrToStructure(
                    pSystemInfo,
                    typeof(PROCESS_BASIC_INFORMATION64));

                Console.WriteLine("[+] Got current process basic information.");
                Console.WriteLine("    [*] ExitStatus      : 0x{0}", pbi.ExitStatus.ToString("X8"));
                Console.WriteLine("    [*] PebBaseAddress  : 0x{0}", pbi.PebBaseAddress.ToString("X8"));
                Console.WriteLine("    [*] BasePriority    : {0}", pbi.BasePriority);
                Console.WriteLine("    [*] UniqueProcessId : {0}", pbi.UniqueProcessId);
                Console.WriteLine("    [*] Buffer Size     : {0} Bytes", NumberOfBytes);
                Console.WriteLine("[*] Check information of this process.");
            }

            Marshal.FreeHGlobal(pSystemInfo);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                Console.Write("[*] Hit [ENTER] to exit this program.");
                Console.ReadLine();
            }

            Console.WriteLine("[*] Done.\n");
        }
    }
}
