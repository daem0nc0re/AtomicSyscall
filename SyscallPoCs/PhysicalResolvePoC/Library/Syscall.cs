using System;
using System.Collections.Generic;
using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;
using PhysicalResolvePoC.Interop;

namespace PhysicalResolvePoC.Library
{
    class Syscall : IDisposable
    {
        /*
         * Global Variables
         */
        private IntPtr asmBuffer = IntPtr.Zero;
        private readonly byte[] syscallBytes = new byte[] {
            0x4C, 0x8B, 0xD1,             // mov r10, rcx
            0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, 0x00 (patched with syscall number)
            0x0F, 0x05,                   // syscall
            0xC3                          // ret
        };
        private readonly Dictionary<string, int> syscallTable = new Dictionary<string, int>();
        private readonly MemoryMappedFile memoryMap;

        /*
         * Helper Functions
         */
        private bool SetSyscallBytes(int syscallNumber)
        {
            if (this.asmBuffer == IntPtr.Zero)
            {
                Console.WriteLine("[-] Buffer for assembly code have not been allocated.");

                return false;
            }

            this.syscallBytes[4] = (byte)(syscallNumber & 0xff);
            this.syscallBytes[5] = (byte)((syscallNumber >> 8) & 0xff);
            this.syscallBytes[6] = (byte)((syscallNumber >> 16) & 0xff);
            this.syscallBytes[7] = (byte)((syscallNumber >> 24) & 0xff);

            try
            {
                Marshal.Copy(this.syscallBytes, 0, this.asmBuffer, this.syscallBytes.Length);

                return true;
            }
            catch
            {
                Console.WriteLine("[-] Failed to write assembly code for syscall.");

                return false;
            }
        }

        /*
         * Constructor and Destructor
         */
        public Syscall(Dictionary<string, int> table)
        {
            if (table.Count > 0)
            {
                this.syscallTable = table;
                this.memoryMap = MemoryMappedFile.CreateNew(
                    null,
                    this.syscallBytes.Length,
                    MemoryMappedFileAccess.ReadWriteExecute);
                var accessor = memoryMap.CreateViewAccessor(
                    0,
                    this.syscallBytes.Length,
                    MemoryMappedFileAccess.ReadWriteExecute);
                this.asmBuffer = accessor.SafeMemoryMappedViewHandle.DangerousGetHandle();

                if (this.asmBuffer == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to allocate memory for assembly code.");

                    return;
                }

                return;
            }
            else
            {
                Console.WriteLine("[-] Input table has no entries.");

                return;
            }
        }


        public void Dispose()
        {
            memoryMap.Dispose();
            this.asmBuffer = IntPtr.Zero;
        }

        /*
         * Helpers
         */
        public bool IsInitialized()
        {
            return this.asmBuffer != IntPtr.Zero;
        }


        /*
         * Syscalls
         */
        public int NtQuerySystemInformation(
            Win32Const.SYSTEM_INFORMATION_CLASS SystemInformationClass,
            IntPtr SystemInformation,
            int SystemInformationLength,
            ref int ReturnLength)
        {
            int ntstatus;
            string nameSyscall = "NtQuerySystemInformation";
            int numSyscall;

            Console.WriteLine("[>] Calling {0} syscall.", nameSyscall);

            if (this.asmBuffer == IntPtr.Zero || this.syscallTable.Count == 0)
            {
                Console.WriteLine("[-] Syscall table is not initialized.\n", nameSyscall);

                return -1;
            }
            else if (!this.syscallTable.ContainsKey(nameSyscall))
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

            var syscall = (Win32Delegate.NtQuerySystemInformation)Marshal.GetDelegateForFunctionPointer(
                this.asmBuffer,
                typeof(Win32Delegate.NtQuerySystemInformation));

            ntstatus = syscall(
                SystemInformationClass,
                SystemInformation,
                SystemInformationLength,
                ref ReturnLength);

            Console.WriteLine("[+] {0} is called successfully.", nameSyscall);
            Console.WriteLine("    |-> {0}", Helpers.GetWin32StatusMessage(ntstatus, true));

            return ntstatus;
        }
    }
}
