using System;
using System.Collections.Generic;

namespace HellsGateResolver.Library
{
    internal class Modules
    {
        public static int ResolveSyscallNumber(string syscallName)
        {
            int nSyscallNumber = -1;

            do
            {
                Dictionary<string, int> table = HellsGate.DumpSyscallNumberFromNtdll();

                if (table.Count == 0)
                {
                    Console.WriteLine("[-] Failed to dump syscall table.");
                    break;
                }

                foreach (var entry in table)
                {
                    if (string.Compare(
                        entry.Key,
                        syscallName,
                        StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        syscallName = entry.Key;
                        nSyscallNumber = entry.Value;
                        break;
                    }
                }

                if (nSyscallNumber == -1)
                {
                    Console.WriteLine("[-] \"{0}\" is not found.", syscallName);
                }
                else
                {
                    Console.WriteLine("[+] Syscall number is resolved successfully.");
                    Console.WriteLine("    [*] Syscall Name   : {0}", syscallName);
                    Console.WriteLine("    [*] Syscall Number : {0} (0x{1})", nSyscallNumber, nSyscallNumber.ToString("X"));
                }
            } while (false);

            Console.WriteLine("[*] Done.");

            return nSyscallNumber;
        }
    }
}
