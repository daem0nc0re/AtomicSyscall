using System;
using System.Collections.Generic;
using System.Diagnostics;
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
            ulong pPeb64;
            string pathName;
            IntPtr hProcess = Process.GetCurrentProcess().Handle;
            List<LDR_DATA_TABLE_ENTRY64> x64ModuleLists;

            Console.WriteLine();

            pPeb64 = Utilities.GetPeb64();

            if (!Utilities.GetPeb64Data(hProcess, pPeb64, out PEB64_PARTIAL peb64))
            {
                Console.WriteLine("[-] Failed to read ntdll!_PEB.");

                return;
            }
            else
            {
                Console.WriteLine("ntdll!_PEB64 @ 0x{0}", pPeb64.ToString("X16"));
                Console.WriteLine("    InheritedAddressSpace    : {0}", peb64.InheritedAddressSpace.ToString());
                Console.WriteLine("    ReadImageFileExecOptions : {0}", peb64.ReadImageFileExecOptions.ToString());
                Console.WriteLine("    BeingDebugged            : {0}", peb64.BeingDebugged.ToString());
                Console.WriteLine("    ImageBaseAddress         : {0}", peb64.ImageBaseAddress.ToString("X16"));
                Console.WriteLine("    Ldr                      : {0}", peb64.Ldr.ToString("X16"));
            }

            if (!Utilities.GetLdrData(hProcess, peb64, out PEB_LDR_DATA64 ldr))
            {
                Console.WriteLine("[-] Failed to read ntdll!_PEB64.Ldr.");

                return;
            }
            else
            {
                Console.WriteLine("    Ldr.Initialized          : {0}", ldr.Initialized.ToString());
                Console.WriteLine(
                        @"    Ldr.InInitializationOrderModuleList : {{ 0x{0} - 0x{1} }}",
                        ldr.InInitializationOrderModuleList.Flink.ToString("X16"),
                        ldr.InInitializationOrderModuleList.Blink.ToString("X16"));
                Console.WriteLine(
                    @"    Ldr.InLoadOrderModuleList           : {{ 0x{0} - 0x{1} }}",
                    ldr.InLoadOrderModuleList.Flink.ToString("X16"),
                    ldr.InLoadOrderModuleList.Blink.ToString("X16"));
                Console.WriteLine(
                    @"    Ldr.InMemoryOrderModuleList         : {{ 0x{0} - 0x{1} }}",
                    ldr.InMemoryOrderModuleList.Flink.ToString("X16"),
                    ldr.InMemoryOrderModuleList.Blink.ToString("X16"));
            }

            x64ModuleLists = Utilities.Get64BitModuleEntries(pPeb64);

            if (x64ModuleLists.Count > 0)
            {
                Utilities.DumpInMemoryOrderModuleList(
                    hProcess,
                    x64ModuleLists,
                    false,
                    2);
            }

            Console.WriteLine("    SubSystemData     : 0x{0}", peb64.SubSystemData.ToString("X16"));
            Console.WriteLine("    ProcessHeap       : 0x{0}", peb64.ProcessHeap.ToString("X16"));
            Console.WriteLine("    ProcessParameters : 0x{0}", peb64.ProcessParameters.ToString("X16"));

            if (Utilities.ReadProcessParameters(
                hProcess,
                peb64,
                out RTL_USER_PROCESS_PARAMETERS64 parameters,
                out List<string> environments))
            {
                pathName = Utilities.ReadUnicodeString64(hProcess, parameters.CurrentDirectory.DosPath);

                if (!string.IsNullOrEmpty(pathName))
                    Console.WriteLine("    CurrentDirectory  : '{0}'", pathName);
                else
                    Console.WriteLine("    CurrentDirectory  : '<null>'");

                pathName = Utilities.ReadUnicodeString64(hProcess, parameters.WindowTitle);

                if (!string.IsNullOrEmpty(pathName))
                    Console.WriteLine("    WindowTitle       : '{0}'", pathName);
                else
                    Console.WriteLine("    WindowTitle       : '<null>'");

                pathName = Utilities.ReadUnicodeString64(hProcess, parameters.ImagePathName);

                if (!string.IsNullOrEmpty(pathName))
                    Console.WriteLine("    ImageFile         : '{0}'", pathName);
                else
                    Console.WriteLine("    ImageFile         : '<null>'");

                pathName = Utilities.ReadUnicodeString64(hProcess, parameters.CommandLine);

                if (!string.IsNullOrEmpty(pathName))
                    Console.WriteLine("    CommandLine       : '{0}'", pathName);
                else
                    Console.WriteLine("    CommandLine       : '<null>'");

                pathName = Utilities.ReadUnicodeString64(hProcess, parameters.DllPath);

                if (!string.IsNullOrEmpty(pathName))
                    Console.WriteLine("    DllPath           : '{0}'", pathName);
                else
                    Console.WriteLine("    DllPath           : '<null>'");

                if (environments.Count > 0)
                {
                    Console.WriteLine("    Environment:");

                    foreach (var env in environments)
                        Console.WriteLine("        {0}", env);
                }
            }

            Console.WriteLine("[*] Done.");
            Console.WriteLine("[*] Check this process (PID : {0}) with WinDbg or Process Explorer.", Process.GetCurrentProcess().Id);
            Console.WriteLine("[*] To exit this program, hit [ENTER] key.");
            Console.ReadLine();
        }
    }
}
