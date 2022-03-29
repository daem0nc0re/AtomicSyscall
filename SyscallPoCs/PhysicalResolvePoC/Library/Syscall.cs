using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using PhysicalResolvePoC.Interop;

namespace PhysicalResolvePoC.Library
{
    class Syscall
    {
        /*
         * Global Variables
         */
        private static bool isInitialized = false;
        private static IntPtr syscallStub;
        private static byte[] syscallBytes;
        private static Dictionary<string, int> syscallTable = new Dictionary<string, int>();

        /*
         * Helper Functions
         */
        private static void SetSyscallBytes(int syscallNumber)
        {
            byte b0 = (byte)(syscallNumber & 0xff);
            byte b1 = (byte)((syscallNumber >> 8) & 0xff);
            byte b2 = (byte)((syscallNumber >> 16) & 0xff);
            byte b3 = (byte)((syscallNumber >> 24) & 0xff);

            syscallBytes = new byte[] {
                0x4C, 0x8B, 0xD1,     // mov r10, rcx
                0xB8, b0, b1, b2, b3, // mov eax, syscall_number
                0x0F, 0x05,           // syscall
                0xC3                  // ret
            };
        }

        public static bool Initialize(Dictionary<string, int> table)
        {
            if (table.Count > 0)
            {
                syscallTable = table;
                isInitialized = true;

                return true;
            }
            else
            {
                return false;
            }
        }

        /*
         * Syscalls
         */
        public static int NtQuerySystemInformation(
            Win32Const.SYSTEM_INFORMATION_CLASS SystemInformationClass,
            IntPtr SystemInformation,
            int SystemInformationLength,
            ref int ReturnLength)
        {
            int ntstatus;
            string nameSyscall = "NtQuerySystemInformation";
            Win32Const.MemoryProtectionFlags oldProtect = 0;
            int numSyscall;

            Console.WriteLine("[>] Calling {0} syscall.", nameSyscall);

            if (!isInitialized || syscallTable.Count == 0)
            {
                Console.WriteLine("[-] Syscall table is not initialized.\n", nameSyscall);

                return -1;
            }
            else if (!syscallTable.ContainsKey(nameSyscall))
            {
                Console.WriteLine("[-] Failed to resolve {0}.\n", nameSyscall);

                return -1;
            }
            else
            {
                numSyscall = syscallTable[nameSyscall];
                Console.WriteLine(
                    "    |-> Syscall Number : {0} (0x{1})",
                    numSyscall,
                    numSyscall.ToString("X4"));
            }

            SetSyscallBytes(numSyscall);

            syscallStub = Marshal.AllocHGlobal(syscallBytes.Length);
            Marshal.Copy(syscallBytes, 0, syscallStub, syscallBytes.Length);

            var syscall = (Win32Delegate.NtQuerySystemInformation)Marshal.GetDelegateForFunctionPointer(
                syscallStub,
                typeof(Win32Delegate.NtQuerySystemInformation));

            if (!Win32Api.VirtualProtect(
                syscallStub,
                syscallBytes.Length,
                Win32Const.MemoryProtectionFlags.PAGE_EXECUTE_READ,
                ref oldProtect))
            {
                Console.WriteLine("[-] Failed to change memory protection.\n");

                return Marshal.GetLastWin32Error();
            }

            ntstatus = syscall(
                SystemInformationClass,
                SystemInformation,
                SystemInformationLength,
                ref ReturnLength);

            if (!Win32Api.VirtualProtect(
                syscallStub,
                syscallBytes.Length,
                oldProtect,
                ref oldProtect))
            {
                Console.WriteLine("[-] Failed to change memory protection.\n");

                return Marshal.GetLastWin32Error();
            }

            Marshal.FreeHGlobal(syscallStub);
            syscallStub = IntPtr.Zero;

            Console.WriteLine("[+] {0} is called successfully.", nameSyscall);
            Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));

            return ntstatus;
        }
    }
}
