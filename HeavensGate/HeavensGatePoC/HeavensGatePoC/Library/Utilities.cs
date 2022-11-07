using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using HeavensGatePoC.Interop;

namespace HeavensGatePoC.Library
{
    using NTSTATUS = Int32;

    internal class Utilities
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate void ShellcodeType();

        public static ulong GetPeb64()
        {
            IntPtr pContext;
            ShellcodeType invoker;
            string functionName = "GetPeb64";
            var shellcode = new byte[]
            {
                0x65, 0x48, 0x8B, 0x0C, 0x25, 0x60, 0x00, 0x00, 0x00, // mov    rcx,QWORD PTR gs:0x60
                0x48, 0x89, 0x0C, 0x25, 0x44, 0x43, 0x42, 0x41        // mov    QWORD PTR ds:0x41424344,rcx
            };

            if (!HeavensGateFactory.g_ExportTable.ContainsKey(functionName))
            {
                pContext = Marshal.AllocHGlobal(8);
                Marshal.WriteInt64(pContext, 0L);
                Buffer.BlockCopy(BitConverter.GetBytes(pContext.ToInt32()), 0, shellcode, 13, 4);

                HeavensGateFactory.AddShellcode(functionName, shellcode, pContext);
            }
            else
            {
                pContext = HeavensGateFactory.g_ExportTable[functionName].ContextBuffer;
                Marshal.WriteInt64(pContext, 0L);
            }

            invoker = (ShellcodeType)Marshal.GetDelegateForFunctionPointer(
                HeavensGateFactory.g_ExportTable[functionName].FunctionBuffer,
                typeof(ShellcodeType));
            invoker();

            return (ulong)Marshal.ReadInt64(pContext);
        }


        public static Dictionary<string, ulong> Get64BitModuleEntries()
        {
            NTSTATUS ntstatus;
            PEB64_PARTIAL peb64;
            PEB_LDR_DATA64 pebLdrData64;
            LDR_DATA_TABLE_ENTRY64_PARTIAL entry64;
            ulong ldrAddress;
            ulong entryAddress;
            ulong currentEntryAddress;
            ulong dllBaseAddress;
            ulong stringAddress;
            int nStringLength;
            int nStringBufferSize;
            IntPtr pPeb64;
            IntPtr pLdr64;
            IntPtr pEntry64;
            IntPtr pStringBuffer;
            string moduleName;
            int nInMemoryOrderLinksOffset = Marshal.OffsetOf(
                typeof(LDR_DATA_TABLE_ENTRY64_PARTIAL),
                "InMemoryOrderLinks").ToInt32();
            int nPeb64Size = Marshal.SizeOf(typeof(PEB64_PARTIAL));
            int nLdr64Size = Marshal.SizeOf(typeof(PEB_LDR_DATA64));
            int nEntry64Size = Marshal.SizeOf(typeof(LDR_DATA_TABLE_ENTRY64_PARTIAL));
            var entries = new Dictionary<string, ulong>();
            ulong peb64Address = GetPeb64();

            pPeb64 = Marshal.AllocHGlobal(nPeb64Size);
            ntstatus = Syscall.NtReadVirtualMemory(
                new IntPtr(-1),
                peb64Address,
                pPeb64,
                (uint)nPeb64Size,
                IntPtr.Zero);
            peb64 = (PEB64_PARTIAL)Marshal.PtrToStructure(pPeb64, typeof(PEB64_PARTIAL));
            ldrAddress = peb64.Ldr;
            Marshal.FreeHGlobal(pPeb64);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
                return entries;

            pLdr64 = Marshal.AllocHGlobal(nLdr64Size);
            ntstatus = Syscall.NtReadVirtualMemory(
                new IntPtr(-1),
                ldrAddress,
                pLdr64,
                (uint)nLdr64Size,
                IntPtr.Zero);
            pebLdrData64 = (PEB_LDR_DATA64)Marshal.PtrToStructure(pLdr64, typeof(PEB_LDR_DATA64));
            entryAddress = pebLdrData64.InMemoryOrderModuleList.Flink - (ulong)nInMemoryOrderLinksOffset;
            Marshal.FreeHGlobal(pLdr64);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
                return entries;

            do
            {
                currentEntryAddress = entryAddress;
                pEntry64 = Marshal.AllocHGlobal(nEntry64Size);
                ntstatus = Syscall.NtReadVirtualMemory(
                    new IntPtr(-1),
                    currentEntryAddress,
                    pEntry64,
                    (uint)nEntry64Size,
                    IntPtr.Zero);
                entry64 = (LDR_DATA_TABLE_ENTRY64_PARTIAL)Marshal.PtrToStructure(
                    pEntry64,
                    typeof(LDR_DATA_TABLE_ENTRY64_PARTIAL));
                dllBaseAddress = entry64.DllBase;
                entryAddress = entry64.InMemoryOrderLinks.Flink - (ulong)nInMemoryOrderLinksOffset;
                nStringLength = (int)entry64.FullDllName.Length;
                stringAddress = entry64.FullDllName.Buffer;
                Marshal.FreeHGlobal(pEntry64);

                if (ntstatus == Win32Consts.STATUS_SUCCESS)
                {
                    nStringBufferSize = nStringLength + 2;
                    pStringBuffer = Marshal.AllocHGlobal(nStringBufferSize);
                    Marshal.Copy(new byte[nStringBufferSize], 0, pStringBuffer, nStringBufferSize);

                    ntstatus = Syscall.NtReadVirtualMemory(
                        new IntPtr(-1),
                        stringAddress,
                        pStringBuffer,
                        (uint)nStringLength,
                        IntPtr.Zero);

                    moduleName = Path.GetFileName(Marshal.PtrToStringUni(pStringBuffer));
                    Marshal.FreeHGlobal(pStringBuffer);

                    if (ntstatus == Win32Consts.STATUS_SUCCESS)
                    {
                        if (entries.ContainsKey(moduleName))
                            break;
                        else if (dllBaseAddress != 0UL)
                            entries.Add(moduleName, dllBaseAddress);
                    }
                    else
                    {
                        break;
                    }
                }
                else
                {
                    break;
                }
            } while (true);

            return entries;
        }
    }
}
