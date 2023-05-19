using System;

namespace HalosGateResolver.Library
{
    internal class Modules
    {
        public static int ResolveSyscallNumber(string syscallName)
        {
            int nSyscallNumber = HalosGate.ResolveSyscallNumber(ref syscallName);

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

            Console.WriteLine("[*] Done.");

            return nSyscallNumber;
        }
    }
}
