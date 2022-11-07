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

        public static Dictionary<ulong, string> DumpInMemoryOrderModuleList(
            IntPtr hProcess,
            List<LDR_DATA_TABLE_ENTRY64> tableEntries,
            bool is32bit,
            int nIndentCount)
        {
            string line;
            string lineFormat;
            string imagePathName;
            string dllLoadedTime;
            string addressFormat = is32bit ? "X8" : "X16";
            string headerBase = "Base";
            string headerReason = "Reason";
            string headerLoaded = "Loaded";
            string headerModule = "Module";
            int nMaxBaseStringLength = is32bit ? 10 : 18;
            int nMaxReasonStringLength = headerReason.Length;
            int nMaxLoadedStringLength = headerLoaded.Length;
            int nMaxModuleStringLength = headerModule.Length;
            var dictionaryDll = new Dictionary<ulong, string>();

            if (tableEntries.Count == 0)
                return dictionaryDll;

            foreach (var table in tableEntries)
            {
                imagePathName = Utilities.ReadUnicodeString64(hProcess, table.FullDllName);
                dllLoadedTime = Helpers.ConvertLargeIntegerToLocalTimeString(table.LoadTime);

                if (string.IsNullOrEmpty(imagePathName))
                    imagePathName = "N/A";

                dictionaryDll.Add(table.DllBase, imagePathName);

                if (table.LoadReason.ToString().Length > nMaxReasonStringLength)
                    nMaxReasonStringLength = table.LoadReason.ToString().Length;

                if (dictionaryDll[table.DllBase].Length > nMaxModuleStringLength)
                    nMaxModuleStringLength = imagePathName.Length;

                if (dllLoadedTime.Length > nMaxLoadedStringLength)
                    nMaxLoadedStringLength = dllLoadedTime.Length;
            }

            lineFormat = string.Format(
                "{0}{{0,{1}}} {{1,-{2}}} {{2,-{3}}} {{3,-{4}}}",
                new string(' ', nIndentCount * 4),
                nMaxBaseStringLength,
                nMaxReasonStringLength,
                nMaxLoadedStringLength,
                nMaxModuleStringLength);

            line = string.Format(lineFormat, headerBase, headerReason, headerLoaded, headerModule);
            Console.WriteLine(line.TrimEnd());

            foreach (var table in tableEntries)
            {
                line = string.Format(
                    lineFormat,
                    string.Format("0x{0}", table.DllBase.ToString(addressFormat)),
                    table.LoadReason.ToString(),
                    Helpers.ConvertLargeIntegerToLocalTimeString(table.LoadTime),
                    dictionaryDll[table.DllBase]);
                Console.WriteLine(line.TrimEnd());
            }

            return dictionaryDll;
        }

        public static bool GetLdrData(
            IntPtr hProcess,
            PEB64_PARTIAL peb64,
            out PEB_LDR_DATA64 ldr)
        {
            NTSTATUS ntstatus;
            bool status;
            int nBufferSize = Marshal.SizeOf(typeof(PEB_LDR_DATA64));
            IntPtr pLdr = Marshal.AllocHGlobal(nBufferSize);

            ntstatus = Syscall.NtReadVirtualMemory(
                hProcess,
                peb64.Ldr,
                pLdr,
                (uint)nBufferSize,
                out uint nReturnedBytes);

            if ((ntstatus == Win32Consts.STATUS_SUCCESS) && nReturnedBytes > 0)
            {
                status = true;
                ldr = (PEB_LDR_DATA64)Marshal.PtrToStructure(
                    pLdr,
                    typeof(PEB_LDR_DATA64));
            }
            else
            {
                status = false;
                ldr = new PEB_LDR_DATA64();
            }

            return status;
        }

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


        public static bool GetPeb64Data(
            IntPtr hProcess,
            ulong peb64Address,
            out PEB64_PARTIAL peb64)
        {
            NTSTATUS ntstatus;
            bool status;
            int nBufferSize = Marshal.SizeOf(typeof(PEB64_PARTIAL));
            IntPtr pPeb64Data = Marshal.AllocHGlobal(nBufferSize);

            ntstatus = Syscall.NtReadVirtualMemory(
                hProcess,
                peb64Address,
                pPeb64Data,
                (uint)nBufferSize,
                out uint nReturnedBytes);

            if ((ntstatus == Win32Consts.STATUS_SUCCESS) && nReturnedBytes > 0)
            {
                status = true;
                peb64 = (PEB64_PARTIAL)Marshal.PtrToStructure(
                    pPeb64Data,
                    typeof(PEB64_PARTIAL));
            }
            else
            {
                status = false;
                peb64 = new PEB64_PARTIAL();
            }

            return status;
        }


        public static List<LDR_DATA_TABLE_ENTRY64> Get64BitModuleEntries(ulong peb64Address)
        {
            NTSTATUS ntstatus;
            PEB64_PARTIAL peb64;
            PEB_LDR_DATA64 pebLdrData64;
            LDR_DATA_TABLE_ENTRY64 entry64;
            ulong ldrAddress;
            ulong entryAddress;
            ulong currentEntryAddress;
            IntPtr pPeb64;
            IntPtr pLdr64;
            IntPtr pEntry64;
            int nInMemoryOrderLinksOffset = Marshal.OffsetOf(
                typeof(LDR_DATA_TABLE_ENTRY64),
                "InMemoryOrderLinks").ToInt32();
            int nPeb64Size = Marshal.SizeOf(typeof(PEB64_PARTIAL));
            int nLdr64Size = Marshal.SizeOf(typeof(PEB_LDR_DATA64));
            int nEntry64Size = Marshal.SizeOf(typeof(LDR_DATA_TABLE_ENTRY64));
            var entries = new List<LDR_DATA_TABLE_ENTRY64>();
            var baseAddressList = new List<ulong>();

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
                entry64 = (LDR_DATA_TABLE_ENTRY64)Marshal.PtrToStructure(
                    pEntry64,
                    typeof(LDR_DATA_TABLE_ENTRY64));
                entryAddress = entry64.InMemoryOrderLinks.Flink - (ulong)nInMemoryOrderLinksOffset;
                Marshal.FreeHGlobal(pEntry64);

                if (ntstatus == Win32Consts.STATUS_SUCCESS)
                {
                    if (baseAddressList.Contains(entry64.DllBase))
                    {
                        break;
                    }
                    else if (entry64.DllBase != 0UL)
                    {
                        baseAddressList.Add(entry64.DllBase);
                        entries.Add(entry64);
                    }
                }
                else
                {
                    break;
                }
            } while (true);

            return entries;
        }


        public static string ReadUnicodeString64(
            IntPtr hProcess,
            UNICODE_STRING64 unicodeString64)
        {
            NTSTATUS ntstatus;
            string result;
            int nBufferSize = (int)unicodeString64.MaximumLength;
            IntPtr pUnicodeBuffer = Marshal.AllocHGlobal(nBufferSize);
            Marshal.Copy(new byte[nBufferSize], 0, pUnicodeBuffer, nBufferSize);

            ntstatus = Syscall.NtReadVirtualMemory(
                hProcess,
                unicodeString64.Buffer,
                pUnicodeBuffer,
                (uint)nBufferSize,
                out uint nReturnedLength);

            if ((ntstatus == Win32Consts.STATUS_SUCCESS) && (nReturnedLength > 0))
                result = Marshal.PtrToStringUni(pUnicodeBuffer);
            else
                result = null;

            return result;
        }


        public static bool ReadProcessParameters(
            IntPtr hProcess,
            PEB64_PARTIAL peb64,
            out RTL_USER_PROCESS_PARAMETERS64 parameters,
            out List<string> environments)
        {
            NTSTATUS ntstatus;
            IntPtr pEnvironment;
            IntPtr pUnicodeString;
            string unicodeString;
            int offset = 0;
            int nBufferSize = Marshal.SizeOf(typeof(RTL_USER_PROCESS_PARAMETERS64));
            IntPtr pParametersBuffer = Marshal.AllocHGlobal(nBufferSize);
            environments = new List<string>();

            ntstatus = Syscall.NtReadVirtualMemory(
                hProcess,
                peb64.ProcessParameters,
                pParametersBuffer,
                (uint)nBufferSize,
                out uint nReturnedSize);

            if ((ntstatus == Win32Consts.STATUS_SUCCESS) && (nReturnedSize > 0))
            {
                parameters = (RTL_USER_PROCESS_PARAMETERS64)Marshal.PtrToStructure(
                    pParametersBuffer,
                    typeof(RTL_USER_PROCESS_PARAMETERS64));
            }
            else
            {
                Marshal.FreeHGlobal(pParametersBuffer);
                parameters = new RTL_USER_PROCESS_PARAMETERS64();

                return false;
            }

            nBufferSize = (int)parameters.EnvironmentSize;
            pEnvironment = Marshal.AllocHGlobal(nBufferSize);
            Marshal.Copy(new byte[nBufferSize], 0, pEnvironment, nBufferSize);

            ntstatus = Syscall.NtReadVirtualMemory(
                hProcess,
                parameters.Environment,
                pEnvironment,
                (uint)nBufferSize,
                out nReturnedSize);

            if ((ntstatus == Win32Consts.STATUS_SUCCESS) && (nReturnedSize > 0))
            {
                do
                {
                    pUnicodeString = new IntPtr(pEnvironment.ToInt32() + offset);
                    unicodeString = Marshal.PtrToStringUni(pUnicodeString).Trim('\x00');
                    environments.Add(unicodeString);
                    offset += ((unicodeString.Length * 2) + 2);
                } while (offset < nBufferSize);
            }

            Marshal.FreeHGlobal(pEnvironment);

            return true;
        }
    }
}
