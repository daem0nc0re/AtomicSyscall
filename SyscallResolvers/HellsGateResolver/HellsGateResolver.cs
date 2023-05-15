using System;
using System.Collections.Generic;
using HellsGateResolver.Library;

namespace HellsGateResolver
{
    class HellsGateResolver
    {
        static void Main(string[] args)
        {
            Console.WriteLine("\n--[ Hell's Gate syscall number resolver\n");

            if (args.Length == 0)
            {
                Console.WriteLine(
                    "Usage: {0} <Syscall Name in ntdll.dll>\n",
                    AppDomain.CurrentDomain.FriendlyName);

                return;
            }

            string target;
            var status = false;

            if (args[0].IndexOf("Nt", StringComparison.OrdinalIgnoreCase) == 0)
            {
                target = args[0];
            }
            else
            {
                Console.WriteLine("[-] Syscall name should be start with \"Nt\".");

                return;
            }

            Dictionary<string, int> table = HellsGate.DumpSyscallNumberFromNtdll();

            foreach (var entry in table)
            {
                if (string.Compare(
                    entry.Key,
                    target,
                    StringComparison.OrdinalIgnoreCase) == 0)
                {
                    status = true;
                    Console.WriteLine("[+] Found.");
                    Console.WriteLine("    [*] Syscall Name   : {0}", entry.Key);
                    Console.WriteLine("    [*] Syscall Number : {0} (0x{1})", entry.Value, entry.Value.ToString("X"));
                    break;
                }
            }

            if (!status)
                Console.WriteLine("[-] Failed to resolve syscall number.");

            Console.WriteLine("[*] Done.\n");
        }
    }
}
