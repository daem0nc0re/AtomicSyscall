using System;
using System.Collections.Generic;
using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;
using HeavensGatePoC.Interop;

namespace HeavensGatePoC.Library
{
    using NTSTATUS = Int32;

    internal class Syscall : IDisposable
    {
        /*
         * Global Variables
         */
        private IntPtr getHeavensGateAddressBuffer = IntPtr.Zero;
        private IntPtr syscallBuffer = IntPtr.Zero;
        private IntPtr heavensGatePointerBuffer = IntPtr.Zero;
        private int numberOfParameters = 0;
        private readonly byte[] getHeavensGateAddressBytes = new byte[] {
            0x64, 0xA1, 0xC0, 0x00, 0x00, 0x00, // mov  eax, [fs:0xC0]
            0xC3                                // ret
        };
        private readonly byte[] heavensGateBytes = new byte[] {
            0xB8, 0x00, 0x00, 0x00, 0x00,       // mov  eax, syscallNumber
            0xFF, 0x15, 0x00, 0x00, 0x00, 0x00, // call dword ptr [pHeavensGate]
            0xC2, 0x00                          // ret  0x??
        };
        private readonly Dictionary<string, int> syscallTable = new Dictionary<string, int>();
        private readonly List<MemoryMappedFile> memoryMaps = new List<MemoryMappedFile>();

        /*
         * DelegateTypes
         */
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr GetHeavensGateAddressType();

        /*
         * Helper Functions
         */
        public IntPtr GetHeavensGateAddress()
        {
            if (this.getHeavensGateAddressBuffer == IntPtr.Zero)
                return IntPtr.Zero;

            var invoker = (GetHeavensGateAddressType)Marshal.GetDelegateForFunctionPointer(
                this.getHeavensGateAddressBuffer,
                typeof(GetHeavensGateAddressType));

            return invoker();
        }


        private IntPtr SetExecutableCode(byte[] code)
        {
            IntPtr pBuffer;
            MemoryMappedFile memMap;
            MemoryMappedViewAccessor accessor;

            memMap = MemoryMappedFile.CreateNew(
                null,
                code.Length,
                MemoryMappedFileAccess.ReadWriteExecute);
            accessor = memMap.CreateViewAccessor(
                0,
                code.Length,
                MemoryMappedFileAccess.ReadWriteExecute);
            pBuffer = accessor.SafeMemoryMappedViewHandle.DangerousGetHandle();

            if (pBuffer == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to allocate memory for assembly code.");
            }
            else
            {
                Marshal.Copy(code, 0, pBuffer, code.Length);
                this.memoryMaps.Add(memMap);
            }

            return pBuffer;
        }


        private void SetHeavensGate(IntPtr pHeavensGate)
        {
            if (this.heavensGatePointerBuffer == IntPtr.Zero)
                this.heavensGatePointerBuffer = Marshal.AllocHGlobal(IntPtr.Size);

            Marshal.WriteIntPtr(this.heavensGatePointerBuffer, pHeavensGate);
            Marshal.WriteInt32(this.syscallBuffer, 7, this.heavensGatePointerBuffer.ToInt32());
        }


        private void SetSyscallNumber(int syscallNumber)
        {
            Marshal.WriteInt32(this.syscallBuffer, 1, syscallNumber);

            if (numberOfParameters == 0)
            {
                Marshal.WriteByte(this.syscallBuffer, 11, 0xC3);
                Marshal.WriteByte(this.syscallBuffer, 12, 0x00);
            }
            else
            {
                Marshal.WriteByte(this.syscallBuffer, 11, 0xC2);
                Marshal.WriteByte(this.syscallBuffer, 12, (byte)(this.numberOfParameters * 4));
            }
        }

        /*
         * Constructor and Destructor
         */
        public Syscall(Dictionary<string, int> table)
        {
            IntPtr pBuffer;
            IntPtr pHeavensGate;

            if (table.Count > 0)
            {
                this.syscallTable = table;

                if (this.syscallTable.Count == 0)
                    throw new ArgumentException("Syscall table is null.");

                pBuffer = SetExecutableCode(this.getHeavensGateAddressBytes);

                if (pBuffer == IntPtr.Zero)
                    throw new InsufficientMemoryException("Failed to allocate buffer.");
                else
                    this.getHeavensGateAddressBuffer = pBuffer;

                pBuffer = SetExecutableCode(this.heavensGateBytes);

                if (pBuffer == IntPtr.Zero)
                    throw new InsufficientMemoryException("Failed to allocate buffer.");
                else
                    this.syscallBuffer = pBuffer;

                pHeavensGate = GetHeavensGateAddress();

                if (pHeavensGate == IntPtr.Zero)
                    throw new InvalidOperationException("Failed to resolve Heaven's Gate address.");

                SetHeavensGate(pHeavensGate);
            }
            else
            {
                Console.WriteLine("[-] Input table has no entries.");
            }
        }


        public void Dispose()
        {
            foreach (var memMap in this.memoryMaps)
                memMap.Dispose();

            this.memoryMaps.Clear();

            if (this.heavensGatePointerBuffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(this.heavensGatePointerBuffer);
                this.heavensGatePointerBuffer = IntPtr.Zero;
            }
        }


        /*
         * Syscalls
         */
        public NTSTATUS NtQueryInformationProcess(
            IntPtr ProcessHandle,
            PROCESS_INFORMATION_CLASS ProcessInformationClass,
            IntPtr ProcessInformation,
            uint ProcessInformationLength,
            IntPtr pReturnLength)
        {
            NTSTATUS ntstatus;
            int numSyscall;
            string nameSyscall = "NtQueryInformationProcess";
            this.numberOfParameters = 5;

            Console.WriteLine("[>] Calling {0} syscall.", nameSyscall);

            if (this.syscallBuffer == IntPtr.Zero || this.syscallTable.Count == 0)
            {
                Console.WriteLine("[-] Syscall table is not initialized.\n");

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

            SetSyscallNumber(numSyscall);

            var syscall = (NativeMethods.NtQueryInformationProcess)Marshal.GetDelegateForFunctionPointer(
                this.syscallBuffer,
                typeof(NativeMethods.NtQueryInformationProcess));

            ntstatus = syscall(
                ProcessHandle,
                ProcessInformationClass,
                ProcessInformation,
                ProcessInformationLength,
                pReturnLength);

            Console.WriteLine("[+] {0} is called successfully.", nameSyscall);
            Console.WriteLine("    |-> {0}", Helpers.GetWin32ErrorMessage(ntstatus, true));

            return ntstatus;
        }
    }
}
