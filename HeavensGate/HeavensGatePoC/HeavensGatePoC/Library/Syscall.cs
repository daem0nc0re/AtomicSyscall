using System;
using System.Collections.Generic;
using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;
using HeavensGatePoC.Interop;

namespace HeavensGatePoC.Library
{
    using NTSTATUS = Int32;

    internal class Syscall
    {
        /*
         * Delegate Types
         */
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate NTSTATUS SyscallType();

        /*
         * Syscalls
         */
        public static NTSTATUS NtQueryInformationProcess(
            IntPtr ProcessHandle,
            PROCESSINFOCLASS ProcessInformationClass,
            IntPtr ProcessInformation,
            uint ProcessInformationLength,
            out uint ReturnLength)
        {
            NTSTATUS ntstatus;
            IntPtr pReturnLength = Marshal.AllocHGlobal(4);
            Marshal.WriteInt32(pReturnLength, 0);

            ntstatus = NtQueryInformationProcess(
                ProcessHandle,
                ProcessInformationClass,
                ProcessInformation,
                ProcessInformationLength,
                pReturnLength);

            ReturnLength = (uint)Marshal.ReadInt32(pReturnLength);
            Marshal.FreeHGlobal(pReturnLength);

            return ntstatus;
        }


        public static NTSTATUS NtQueryInformationProcess(
            IntPtr ProcessHandle,
            PROCESSINFOCLASS ProcessInformationClass,
            IntPtr ProcessInformation,
            uint ProcessInformationLength,
            IntPtr pReturnLength)
        {
            NTSTATUS ntstatus;
            SyscallType invoker;
            IntPtr pParameters;
            string syscallName = "NtQueryInformationProcess";
            int numberOfParameters = 5;
            var parameters = new long[numberOfParameters];

            if (!HeavensGateFactory.g_ExportTable.ContainsKey(syscallName))
                HeavensGateFactory.AddSyscall(syscallName, numberOfParameters);

            // Set parameters
            pParameters = HeavensGateFactory.g_ExportTable[syscallName].ContextBuffer;
            parameters[0] = ProcessHandle.ToInt64();
            parameters[1] = (long)ProcessInformationClass;
            parameters[2] = ProcessInformation.ToInt64();
            parameters[3] = (long)ProcessInformationLength;
            parameters[4] = pReturnLength.ToInt64();
            Marshal.Copy(parameters, 0, pParameters, numberOfParameters);

            // Invoke syscall
            invoker = (SyscallType)Marshal.GetDelegateForFunctionPointer(
                HeavensGateFactory.g_ExportTable[syscallName].FunctionBuffer,
                typeof(SyscallType));
            ntstatus = invoker();

            return ntstatus;
        }


        public static NTSTATUS NtReadVirtualMemory(
            IntPtr ProcessHandle,
            ulong BaseAddress,
            IntPtr Buffer,
            uint BufferSize,
            out uint NumberOfBytesRead)
        {
            NTSTATUS ntstatus;
            IntPtr pNumberOfBytesRead = Marshal.AllocHGlobal(4);
            Marshal.WriteInt32(pNumberOfBytesRead, 0);

            ntstatus = NtReadVirtualMemory(
                ProcessHandle,
                BaseAddress,
                Buffer,
                BufferSize,
                pNumberOfBytesRead);

            NumberOfBytesRead = (uint)Marshal.ReadInt32(pNumberOfBytesRead);
            Marshal.FreeHGlobal(pNumberOfBytesRead);

            return ntstatus;
        }


        public static NTSTATUS NtReadVirtualMemory(
            IntPtr ProcessHandle,
            ulong BaseAddress,
            IntPtr Buffer,
            uint BufferSize,
            IntPtr pNumberOfBytesRead)
        {
            NTSTATUS ntstatus;
            SyscallType invoker;
            IntPtr pParameters;
            string syscallName = "NtReadVirtualMemory";
            int numberOfParameters = 5;
            var parameters = new long[numberOfParameters];

            if (!HeavensGateFactory.g_ExportTable.ContainsKey(syscallName))
                HeavensGateFactory.AddSyscall(syscallName, numberOfParameters);

            // Set parameters
            pParameters = HeavensGateFactory.g_ExportTable[syscallName].ContextBuffer;
            parameters[0] = ProcessHandle.ToInt64();
            parameters[1] = (long)BaseAddress;
            parameters[2] = Buffer.ToInt64();
            parameters[3] = (long)BufferSize;
            parameters[4] = pNumberOfBytesRead.ToInt64();
            Marshal.Copy(parameters, 0, pParameters, numberOfParameters);

            // Invoke syscall
            invoker = (SyscallType)Marshal.GetDelegateForFunctionPointer(
                HeavensGateFactory.g_ExportTable[syscallName].FunctionBuffer,
                typeof(SyscallType));
            ntstatus = invoker();

            return ntstatus;
        }
    }
}
