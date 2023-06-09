using System;
using System.Collections.Generic;
using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;
using HellsGatePoC.Interop;

namespace HellsGatePoC.Library
{
    internal class Syscall : IDisposable
    {
        /*
         * Global Variables
         */
        private IntPtr asmBuffer = IntPtr.Zero;
        private short numberOfParameters = 0;
        private readonly byte[] syscallBytesX86 = new byte[] {
            0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, 0x00 (patched with syscall number)
            0xE8, 0x03, 0x00, 0x00, 0x00, // call _syscall -|
            0xC2, 0x00, 0x00,             // retn 0x??      | <-|
            0x8B, 0xD4,                   // mov edx, esp <-|   |
            0x0F, 0x34,                   // sysenter           |
            0xC3                          // ret ---------------|
        };
        private readonly byte[] syscallBytesX64 = new byte[] {
            0x4C, 0x8B, 0xD1,             // mov r10, rcx
            0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, 0x00 (patched with syscall number)
            0x0F, 0x05,                   // syscall
            0xC3                          // ret
        };
        private readonly byte[] syscallBytesArm64 = new byte[] {
            0x00, 0x00, 0x00, 0x00, // svc #0x??
            0xC0, 0x03, 0x5F, 0xD6  // ret
        };
        private readonly Dictionary<string, int> syscallTable = new Dictionary<string, int>();
        private readonly MemoryMappedFile memoryMap;

        /*
         * Helper Functions
         */
        private bool SetSyscallBytes(int syscallNumber)
        {
            string architecture = Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE");

            if (this.asmBuffer == IntPtr.Zero)
            {
                Console.WriteLine("[-] Buffer for assembly code have not been allocated.");

                return false;
            }

            try
            {
                if (Helpers.CompareIgnoreCase(architecture, "x86"))
                {
                    // Patch syscall number
                    Marshal.WriteInt32(this.asmBuffer, 1, syscallNumber);
                    // Patch retn instruction's immediate value
                    Marshal.WriteInt16(this.asmBuffer, 11, (short)(numberOfParameters * 4));
                }
                else if (Helpers.CompareIgnoreCase(architecture, "AMD64"))
                {
                    // Patch syscall number
                    Marshal.WriteInt32(this.asmBuffer, 4, syscallNumber);
                }
                else if (Helpers.CompareIgnoreCase(architecture, "ARM64"))
                {
                    // Patch svc instruction
                    Marshal.WriteInt32(this.asmBuffer, (int)(0xD4000001 | (syscallNumber << 5)));
                }
                else
                {
                    Console.WriteLine("[-] Unsupported architecture.");

                    return false;
                }

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
            byte[] syscallBytes;
            string architecture = Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE");

            if (Helpers.CompareIgnoreCase(architecture, "x86"))
            {
                syscallBytes = this.syscallBytesX86;
            }
            else if (Helpers.CompareIgnoreCase(architecture, "AMD64"))
            {
                syscallBytes = this.syscallBytesX64;
            }
            else if (Helpers.CompareIgnoreCase(architecture, "ARM64"))
            {
                syscallBytes = this.syscallBytesArm64;
            }
            else
            {
                Console.WriteLine("[-] Unsupported architecture.");

                return;
            }

            if (table.Count > 0)
            {
                this.syscallTable = table;
                this.memoryMap = MemoryMappedFile.CreateNew(
                    null,
                    syscallBytes.Length,
                    MemoryMappedFileAccess.ReadWriteExecute);
                var accessor = memoryMap.CreateViewAccessor(
                    0,
                    syscallBytes.Length,
                    MemoryMappedFileAccess.ReadWriteExecute);
                this.asmBuffer = accessor.SafeMemoryMappedViewHandle.DangerousGetHandle();

                if (this.asmBuffer == IntPtr.Zero)
                    Console.WriteLine("[-] Failed to allocate memory for assembly code.");
                else
                    Marshal.Copy(syscallBytes, 0, this.asmBuffer, syscallBytes.Length);
            }
            else
            {
                Console.WriteLine("[-] Input table has no entries.");
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
            SYSTEM_INFORMATION_CLASS SystemInformationClass,
            IntPtr SystemInformation,
            int SystemInformationLength,
            ref int ReturnLength)
        {
            int ntstatus;
            int numSyscall;
            string nameSyscall = "NtQuerySystemInformation";
            this.numberOfParameters = 4;

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
                    "    [*] Syscall Number : {0} (0x{1})",
                    numSyscall,
                    numSyscall.ToString("X4"));
            }

            SetSyscallBytes(numSyscall);

            var syscall = (NativeMethods.NtQuerySystemInformation)Marshal.GetDelegateForFunctionPointer(
                this.asmBuffer,
                typeof(NativeMethods.NtQuerySystemInformation));

            ntstatus = syscall(
                SystemInformationClass,
                SystemInformation,
                SystemInformationLength,
                ref ReturnLength);

            Console.WriteLine("[+] {0} is called successfully.", nameSyscall);
            Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));

            return ntstatus;
        }
    }
}
