using System;
using System.Collections.Generic;
using System.Linq;

namespace HalosGateResolver.Library
{
    internal class Modules
    {
        public static int ResolveSyscallNumber(string syscallName)
        {
            int nSyscallNumber = -1;

            Dictionary<string, int> table = HalosGate.ResolveSyscallNumber(syscallName);

            if (table.Count == 0)
            {
                Console.WriteLine("[-] \"{0}\" is not found.", syscallName);
            }
            else
            {
                syscallName = table.First().Key;
                nSyscallNumber = table.First().Value;

                Console.WriteLine("[+] Syscall number is resolved successfully.");
                Console.WriteLine("    [*] Syscall Name   : {0}", syscallName);
                Console.WriteLine("    [*] Syscall Number : {0} (0x{1})", nSyscallNumber, nSyscallNumber.ToString("X"));
            }

            Console.WriteLine("[*] Done.");

            return nSyscallNumber;
        }
    }
}
