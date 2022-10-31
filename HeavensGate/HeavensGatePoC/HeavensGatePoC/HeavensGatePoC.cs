using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
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

            if (Environment.Is64BitProcess)
            {
                Console.WriteLine("\n[!] Should be built as 32bit binary.\n");

                return;
            }

            var syscallTable = PhysicalResolve.DumpSyscallNumber(@"C:\Windows\System32\ntdll.dll");
            var syscall = new Syscall(syscallTable);

            /*
             * Enumerate Drivers
             */
            NTSTATUS ntstatus;
            NTSTATUS STATUS_SUCCESS = 0;
            IntPtr pSystemInfo;
            PROCESS_BASIC_INFORMATION pbi;
            int nBufferSize = Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION));

            Console.WriteLine("[>] Trying to get current process information.");

            pSystemInfo = Marshal.AllocHGlobal(nBufferSize);
            Helpers.ZeroMemory(pSystemInfo, nBufferSize);

            ntstatus = syscall.NtQueryInformationProcess(
                Process.GetCurrentProcess().Handle,
                PROCESS_INFORMATION_CLASS.ProcessBasicInformation,
                pSystemInfo,
                (uint)nBufferSize,
                IntPtr.Zero);

            if (ntstatus != STATUS_SUCCESS)
            {
                Console.WriteLine("[-] Failed to get current process basic information.");
            }
            else
            {
                pbi = (PROCESS_BASIC_INFORMATION)Marshal.PtrToStructure(
                    pSystemInfo,
                    typeof(PROCESS_BASIC_INFORMATION));

                Console.WriteLine("[+] Got current process basic information.");
                Console.WriteLine("    [*] ExitStatus      : 0x{0}", pbi.ExitStatus.ToString("X8"));
                Console.WriteLine("    [*] PebBaseAddress  : 0x{0}", pbi.PebBaseAddress.ToString("X8"));
                Console.WriteLine("    [*] BasePriority    : {0}", pbi.BasePriority);
                Console.WriteLine("    [*] UniqueProcessId : {0}", pbi.UniqueProcessId.ToUInt32());
                Console.WriteLine("[*] Check information of this process.");
            }

            Marshal.FreeHGlobal(pSystemInfo);
            syscall.Dispose();

            if (ntstatus == STATUS_SUCCESS)
            {
                Console.Write("[*] Hit [ENTER] to exit this program.");
                Console.ReadLine();
            }

            Console.WriteLine("[*] Done.\n");
        }
    }
}
