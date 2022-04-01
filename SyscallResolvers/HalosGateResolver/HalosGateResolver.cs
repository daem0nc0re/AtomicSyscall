using System;
using System.Collections.Generic;
using HalosGateResolver.Library;

namespace HalosGateResolver
{
    class HalosGateResolver
    {
        static void Main(string[] args)
        {
            Console.WriteLine("\n--[ Halo's Gate syscall number resolver\n");

            if (args.Length == 0)
            {
                Console.WriteLine(
                    "Usage: {0} <Syscall Name in ntdll.dll>\n",
                    AppDomain.CurrentDomain.FriendlyName);

                return;
            }

            string target;

            if (args[0].IndexOf("Nt", StringComparison.OrdinalIgnoreCase) == 0)
            {
                target = args[0];
            }
            else
            {
                Console.WriteLine("[-] Syscall name should be start with \"Nt\".");

                return;
            }

            Dictionary<string, int> table = HalosGate.ResolveSyscallNumber(target);

            if (table.Count > 0)
            {
                foreach (var entry in table)
                {
                    Console.WriteLine("[+] Found.");
                    Console.WriteLine("    |-> Syscall Name   : {0}", entry.Key);
                    Console.WriteLine("    |-> Syscall Number : {0} (0x{1})\n", entry.Value, entry.Value.ToString("X"));
                }
            }
            else
            {
                Console.WriteLine("[-] Failed to resolve syscall number.\n");
            }
        }
    }
}
