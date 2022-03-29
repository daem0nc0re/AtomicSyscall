using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using HellsGatePoC.Interop;

namespace HellsGatePoC.Library
{
    class HellsGate
    {
        /*
         * Definisions for PE header
         */
        public enum DllCharacteristicsType : ushort
        {
            RES_0 = 0x0001,
            RES_1 = 0x0002,
            RES_2 = 0x0004,
            RES_3 = 0x0008,
            IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE = 0x0040,
            IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY = 0x0080,
            IMAGE_DLL_CHARACTERISTICS_NX_COMPAT = 0x0100,
            IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200,
            IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400,
            IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800,
            RES_4 = 0x1000,
            IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000,
            IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000
        }

        public enum MagicType : ushort
        {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b,
            IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
        }

        public enum SubSystemType : ushort
        {
            IMAGE_SUBSYSTEM_UNKNOWN = 0,
            IMAGE_SUBSYSTEM_NATIVE = 1,
            IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
            IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
            IMAGE_SUBSYSTEM_POSIX_CUI = 7,
            IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
            IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
            IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
            IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
            IMAGE_SUBSYSTEM_EFI_ROM = 13,
            IMAGE_SUBSYSTEM_XBOX = 14
        }

        // Struct
        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public uint VirtualAddress;
            public uint Size;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DOS_HEADER
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public char[] e_magic;    // Magic number
            public ushort e_cblp;     // Bytes on last page of file
            public ushort e_cp;       // Pages in file
            public ushort e_crlc;     // Relocations
            public ushort e_cparhdr;  // Size of header in paragraphs
            public ushort e_minalloc; // Minimum extra paragraphs needed
            public ushort e_maxalloc; // Maximum extra paragraphs needed
            public ushort e_ss;       // Initial (relative) SS value
            public ushort e_sp;       // Initial SP value
            public ushort e_csum;     // Checksum
            public ushort e_ip;       // Initial IP value
            public ushort e_cs;       // Initial (relative) CS value
            public ushort e_lfarlc;   // File address of relocation table
            public ushort e_ovno;     // Overlay number
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public ushort[] e_res1;   // Reserved words
            public ushort e_oemid;    // OEM identifier (for e_oeminfo)
            public ushort e_oeminfo;  // OEM information; e_oemid specific
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public ushort[] e_res2;   // Reserved words
            public int e_lfanew;      // File address of new exe header

            private string GetMagic
            {
                get { return new string(e_magic); }
            }

            public bool IsValid
            {
                get { return GetMagic == "MZ"; }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_EXPORT_DIRECTORY
        {
            public uint Characteristics;
            public uint TimeDateStamp;
            public ushort MajorVersion;
            public ushort MinorVersion;
            public uint Name;
            public uint Base;
            public uint NumberOfFunctions;
            public uint NumberOfNames;
            public uint AddressOfFunctions;
            public uint AddressOfNames;
            public uint AddressOfNameOrdinals;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_FILE_HEADER
        {
            public ushort Machine;
            public ushort NumberOfSections;
            public uint TimeDateStamp;
            public uint PointerToSymbolTable;
            public uint NumberOfSymbols;
            public ushort SizeOfOptionalHeader;
            public ushort Characteristics;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_OPTIONAL_HEADER32
        {
            [FieldOffset(0)]
            public MagicType Magic;

            [FieldOffset(2)]
            public byte MajorLinkerVersion;

            [FieldOffset(3)]
            public byte MinorLinkerVersion;

            [FieldOffset(4)]
            public uint SizeOfCode;

            [FieldOffset(8)]
            public uint SizeOfInitializedData;

            [FieldOffset(12)]
            public uint SizeOfUninitializedData;

            [FieldOffset(16)]
            public uint AddressOfEntryPoint;

            [FieldOffset(20)]
            public uint BaseOfCode;

            // PE32 contains this additional field
            [FieldOffset(24)]
            public uint BaseOfData;

            [FieldOffset(28)]
            public uint ImageBase;

            [FieldOffset(32)]
            public uint SectionAlignment;

            [FieldOffset(36)]
            public uint FileAlignment;

            [FieldOffset(40)]
            public ushort MajorOperatingSystemVersion;

            [FieldOffset(42)]
            public ushort MinorOperatingSystemVersion;

            [FieldOffset(44)]
            public ushort MajorImageVersion;

            [FieldOffset(46)]
            public ushort MinorImageVersion;

            [FieldOffset(48)]
            public ushort MajorSubsystemVersion;

            [FieldOffset(50)]
            public ushort MinorSubsystemVersion;

            [FieldOffset(52)]
            public uint Win32VersionValue;

            [FieldOffset(56)]
            public uint SizeOfImage;

            [FieldOffset(60)]
            public uint SizeOfHeaders;

            [FieldOffset(64)]
            public uint CheckSum;

            [FieldOffset(68)]
            public SubSystemType Subsystem;

            [FieldOffset(70)]
            public DllCharacteristicsType DllCharacteristics;

            [FieldOffset(72)]
            public uint SizeOfStackReserve;

            [FieldOffset(76)]
            public uint SizeOfStackCommit;

            [FieldOffset(80)]
            public uint SizeOfHeapReserve;

            [FieldOffset(84)]
            public uint SizeOfHeapCommit;

            [FieldOffset(88)]
            public uint LoaderFlags;

            [FieldOffset(92)]
            public uint NumberOfRvaAndSizes;

            [FieldOffset(96)]
            public IMAGE_DATA_DIRECTORY ExportTable;

            [FieldOffset(104)]
            public IMAGE_DATA_DIRECTORY ImportTable;

            [FieldOffset(112)]
            public IMAGE_DATA_DIRECTORY ResourceTable;

            [FieldOffset(120)]
            public IMAGE_DATA_DIRECTORY ExceptionTable;

            [FieldOffset(128)]
            public IMAGE_DATA_DIRECTORY CertificateTable;

            [FieldOffset(136)]
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;

            [FieldOffset(144)]
            public IMAGE_DATA_DIRECTORY Debug;

            [FieldOffset(152)]
            public IMAGE_DATA_DIRECTORY Architecture;

            [FieldOffset(160)]
            public IMAGE_DATA_DIRECTORY GlobalPtr;

            [FieldOffset(168)]
            public IMAGE_DATA_DIRECTORY TLSTable;

            [FieldOffset(176)]
            public IMAGE_DATA_DIRECTORY LoadConfigTable;

            [FieldOffset(184)]
            public IMAGE_DATA_DIRECTORY BoundImport;

            [FieldOffset(192)]
            public IMAGE_DATA_DIRECTORY IAT;

            [FieldOffset(200)]
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;

            [FieldOffset(208)]
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;

            [FieldOffset(216)]
            public IMAGE_DATA_DIRECTORY Reserved;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_OPTIONAL_HEADER64
        {
            [FieldOffset(0)]
            public MagicType Magic;

            [FieldOffset(2)]
            public byte MajorLinkerVersion;

            [FieldOffset(3)]
            public byte MinorLinkerVersion;

            [FieldOffset(4)]
            public uint SizeOfCode;

            [FieldOffset(8)]
            public uint SizeOfInitializedData;

            [FieldOffset(12)]
            public uint SizeOfUninitializedData;

            [FieldOffset(16)]
            public uint AddressOfEntryPoint;

            [FieldOffset(20)]
            public uint BaseOfCode;

            [FieldOffset(24)]
            public ulong ImageBase;

            [FieldOffset(32)]
            public uint SectionAlignment;

            [FieldOffset(36)]
            public uint FileAlignment;

            [FieldOffset(40)]
            public ushort MajorOperatingSystemVersion;

            [FieldOffset(42)]
            public ushort MinorOperatingSystemVersion;

            [FieldOffset(44)]
            public ushort MajorImageVersion;

            [FieldOffset(46)]
            public ushort MinorImageVersion;

            [FieldOffset(48)]
            public ushort MajorSubsystemVersion;

            [FieldOffset(50)]
            public ushort MinorSubsystemVersion;

            [FieldOffset(52)]
            public uint Win32VersionValue;

            [FieldOffset(56)]
            public uint SizeOfImage;

            [FieldOffset(60)]
            public uint SizeOfHeaders;

            [FieldOffset(64)]
            public uint CheckSum;

            [FieldOffset(68)]
            public SubSystemType Subsystem;

            [FieldOffset(70)]
            public DllCharacteristicsType DllCharacteristics;

            [FieldOffset(72)]
            public ulong SizeOfStackReserve;

            [FieldOffset(80)]
            public ulong SizeOfStackCommit;

            [FieldOffset(88)]
            public ulong SizeOfHeapReserve;

            [FieldOffset(96)]
            public ulong SizeOfHeapCommit;

            [FieldOffset(104)]
            public uint LoaderFlags;

            [FieldOffset(108)]
            public uint NumberOfRvaAndSizes;

            [FieldOffset(112)]
            public IMAGE_DATA_DIRECTORY ExportTable;

            [FieldOffset(120)]
            public IMAGE_DATA_DIRECTORY ImportTable;

            [FieldOffset(128)]
            public IMAGE_DATA_DIRECTORY ResourceTable;

            [FieldOffset(136)]
            public IMAGE_DATA_DIRECTORY ExceptionTable;

            [FieldOffset(144)]
            public IMAGE_DATA_DIRECTORY CertificateTable;

            [FieldOffset(152)]
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;

            [FieldOffset(160)]
            public IMAGE_DATA_DIRECTORY Debug;

            [FieldOffset(168)]
            public IMAGE_DATA_DIRECTORY Architecture;

            [FieldOffset(176)]
            public IMAGE_DATA_DIRECTORY GlobalPtr;

            [FieldOffset(184)]
            public IMAGE_DATA_DIRECTORY TLSTable;

            [FieldOffset(192)]
            public IMAGE_DATA_DIRECTORY LoadConfigTable;

            [FieldOffset(200)]
            public IMAGE_DATA_DIRECTORY BoundImport;

            [FieldOffset(208)]
            public IMAGE_DATA_DIRECTORY IAT;

            [FieldOffset(216)]
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;

            [FieldOffset(224)]
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;

            [FieldOffset(232)]
            public IMAGE_DATA_DIRECTORY Reserved;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct IMAGE_NT_HEADERS32
        {
            public int Signature;
            public IMAGE_FILE_HEADER FileHeader;
            public IMAGE_OPTIONAL_HEADER32 OptionalHeader;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct IMAGE_NT_HEADERS64
        {
            public int Signature;
            public IMAGE_FILE_HEADER FileHeader;
            public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct LDR_DATA_TABLE_ENTRY
        {
            public LIST_ENTRY InLoadOrderLinks;
            public LIST_ENTRY InMemoryOrderLinks;
            public LIST_ENTRY InInitializationOrderLinks;
            public IntPtr DllBase;
            public IntPtr EntryPoint;
            public uint SizeOfImage;
            public UNICODE_STRING FullDllName;
            public UNICODE_STRING BaseDllName;
            public uint Flags;
            public ushort ObsoleteLoadCount;
            public ushort TlsIndex;
            public LIST_ENTRY HashLinks;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct LIST_ENTRY
        {
            public IntPtr Flink;
            public IntPtr blink;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct PEB_LDR_DATA
        {
            public uint Length;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] Initialized;
            public IntPtr SsHandle;
            public LIST_ENTRY InLoadOrderModuleList;
            public LIST_ENTRY InMemoryOrderModuleList;
            public LIST_ENTRY InInitializationOrderModuleList;
            public IntPtr EntryInProgress;
            public IntPtr ShutdownInProgress;
            public IntPtr ShutdownThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct UNICODE_STRING : IDisposable
        {
            public ushort Length;
            public ushort MaximumLength;
            private IntPtr buffer;

            public UNICODE_STRING(string s)
            {
                Length = (ushort)(s.Length * 2);
                MaximumLength = (ushort)(Length + 2);
                buffer = Marshal.StringToHGlobalUni(s);
            }

            public void Dispose()
            {
                Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;
            }

            public override string ToString()
            {
                return Marshal.PtrToStringUni(buffer);
            }
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr GetPebAddress();

        /*
         * Functions
         */
        private static IntPtr[] SearchBytes(
            IntPtr basePointer,
            int range,
            byte[] searchBytes)
        {
            var results = new List<IntPtr>();
            IntPtr pointer;
            IntPtr offsetPointer;
            bool found;

            for (var count = 0; count < (range - searchBytes.Length); count++)
            {
                found = false;
                pointer = new IntPtr(basePointer.ToInt64() + count);

                for (var position = 0; position < searchBytes.Length; position++)
                {
                    offsetPointer = new IntPtr(pointer.ToInt64() + position);
                    found = (Marshal.ReadByte(offsetPointer) == searchBytes[position]);

                    if (!found)
                        break;
                }

                if (found)
                    results.Add(pointer);
            }

            return results.ToArray();
        }


        public static Dictionary<string, int> DumpSyscallNumberFromNtdll()
        {
            uint rvaExportDirectory;
            var results = new Dictionary<string, int>();

            IntPtr hModule = SearchNtdllBase();

            if (hModule == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to find the base address of ntdll.dll.");

                return results;
            }
            else
            {
                Console.WriteLine("[+] ntdll.dll @ 0x{0}", hModule.ToString("X16"));
            }

            var dosHeader = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(
                hModule,
                typeof(IMAGE_DOS_HEADER));
            var pNtHeader = new IntPtr(hModule.ToInt64() + dosHeader.e_lfanew); 
            var arch = (ushort)Marshal.ReadInt16(new IntPtr(
                pNtHeader.ToInt64() +
                Marshal.SizeOf(typeof(int))));

            if (arch == 0x8664)
            {
                Console.WriteLine("[*] Architecture is x64.");

                var ntHeader = (IMAGE_NT_HEADERS64)Marshal.PtrToStructure(
                    pNtHeader,
                    typeof(IMAGE_NT_HEADERS64));
                rvaExportDirectory = ntHeader.OptionalHeader.ExportTable.VirtualAddress;
            }
            else if (arch == 0x014C)
            {
                Console.WriteLine("[*] Architecture is x86.");

                var ntHeader = (IMAGE_NT_HEADERS32)Marshal.PtrToStructure(
                    pNtHeader,
                    typeof(IMAGE_NT_HEADERS32));
                rvaExportDirectory = ntHeader.OptionalHeader.ExportTable.VirtualAddress;
            }
            else
            {
                Console.WriteLine("[-] Unsupported architecture is detected.");

                return results;
            }

            var pExportDirectory = new IntPtr(hModule.ToInt64() + rvaExportDirectory);
            var exportDirectory = (IMAGE_EXPORT_DIRECTORY)Marshal.PtrToStructure(
                pExportDirectory,
                typeof(IMAGE_EXPORT_DIRECTORY));
            var exportName = Marshal.PtrToStringAnsi(new IntPtr(
                hModule.ToInt64() +
                exportDirectory.Name));

            if (exportName != "ntdll.dll")
            {
                Console.WriteLine("[-] Failed to get ntdll.dll.");

                return results;
            }

            var rgx = new Regex(@"^Nt\S+$");
            var numNames = exportDirectory.NumberOfNames;
            var pExportNames = new IntPtr(hModule.ToInt64() + exportDirectory.AddressOfNames);
            var pExportOrdinals = new IntPtr(hModule.ToInt64() + exportDirectory.AddressOfNameOrdinals);
            var pExportFunctions = new IntPtr(hModule.ToInt64() + exportDirectory.AddressOfFunctions);
            IntPtr pFunctionName;
            IntPtr pFunction;
            short ordinal;
            string functionName;
            IntPtr[] offsets;

            for (var idx = 0; idx < numNames; idx++)
            {
                pFunctionName = new IntPtr(
                    hModule.ToInt64() +
                    Marshal.ReadInt32(new IntPtr(pExportNames.ToInt64() + Marshal.SizeOf(typeof(uint)) * idx)));
                ordinal = Marshal.ReadInt16(new IntPtr(pExportOrdinals.ToInt64() + Marshal.SizeOf(typeof(short)) * idx));
                pFunction = new IntPtr(
                    hModule.ToInt64() +
                    Marshal.ReadInt32(new IntPtr(pExportFunctions.ToInt64() + Marshal.SizeOf(typeof(uint)) * ordinal)));
                functionName = Marshal.PtrToStringAnsi(pFunctionName);

                if (!rgx.IsMatch(functionName))
                    continue;

                if (arch == 0x8664) // x64
                {
                    if (SearchBytes(
                        pFunction,
                        0x20,
                        new byte[] { 0x0F, 0x05 }).Length > 0) // syscall
                    {
                        offsets = SearchBytes(
                            pFunction,
                            0x8,
                            new byte[] { 0xB8 }); // mov eax, 0x????????

                        if (offsets.Length > 0)
                        {
                            results.Add(
                                functionName,
                                Marshal.ReadInt32(new IntPtr(offsets[0].ToInt64() + 1)));
                        }
                    }
                }
                else if (arch == 0x014C) // x86
                {
                    if (SearchBytes(
                        pFunction,
                        0x20,
                        new byte[] { 0x0F, 0x34 }).Length > 0) // sysenter
                    {
                        offsets = SearchBytes(
                            pFunction,
                            0x8,
                            new byte[] { 0xB8 }); // mov eax, 0x????????

                        if (offsets.Length > 0)
                        {
                            results.Add(
                                functionName,
                                Marshal.ReadInt32(new IntPtr(offsets[0].ToInt64() + 1)));
                        }
                    }
                }
            }

            if (results.Count == 0)
                Console.WriteLine("[-] Failed to get syscall numbers.");
            else
                Console.WriteLine("[+] Got {0} syscall(s).", results.Count);

            return results;
        }


        private static IntPtr SearchNtdllBase()
        {
            IntPtr peb;
            IntPtr bufferCode;
            byte[] code;
            Win32Const.MemoryProtectionFlags oldProtect = 0;
            var entries = new List<IntPtr>();
            PEB_LDR_DATA ldr;
            LDR_DATA_TABLE_ENTRY ldrDataTableEntry;
            IntPtr pLdr;
            IntPtr pLdrDataTableEntry;

            Console.WriteLine("[>] Trying to find the base address of ntdll.dll.");

            if (Environment.Is64BitOperatingSystem &&
                !Environment.Is64BitProcess)
            {
                Console.WriteLine("[-] 32 bit process in 64 bit OS is not supported.");

                return IntPtr.Zero;
            }
            else if (Environment.Is64BitOperatingSystem &&
                (IntPtr.Size != 8))
            {
                Console.WriteLine("[-] In 64 bit OS, should be compiled with 64 bit pointer.");

                return IntPtr.Zero;
            }
            else if (!Environment.Is64BitOperatingSystem &&
                (IntPtr.Size != 4))
            {
                Console.WriteLine("[-] In 32 bit OS, should be compiled with 32 bit pointer.");

                return IntPtr.Zero;
            }

            if (Environment.Is64BitOperatingSystem)
            {
                code = new byte[] {
                    0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, // mov rax, gs:[0x60]
                    0xC3                                                  // ret
                };
            }
            else
            {
                code = new byte[] {
                    0x64, 0xA1, 0x30, 0x00, 0x00, 0x00, // mov eax, fs:[0x30]
                    0xC3                                // ret
                };
            }

            bufferCode = Marshal.AllocHGlobal(code.Length);
            Marshal.Copy(code, 0, bufferCode, code.Length);

            var functionPtr = (GetPebAddress)Marshal.GetDelegateForFunctionPointer(
                bufferCode,
                typeof(GetPebAddress));

            if (!Win32Api.VirtualProtect(
                bufferCode,
                code.Length,
                Win32Const.MemoryProtectionFlags.PAGE_EXECUTE_READ,
                ref oldProtect))
            {
                Console.WriteLine("[-] Failed to VirtualProtect.");
                Console.WriteLine("    |-> Error : {0}", Marshal.GetLastWin32Error());

                return IntPtr.Zero;
            }

            peb = functionPtr();

            if (!Win32Api.VirtualProtect(
                bufferCode,
                code.Length,
                oldProtect,
                ref oldProtect))
            {
                Console.WriteLine("[-] Failed to VirtualProtect.");
                Console.WriteLine("    |-> Error : {0}", Marshal.GetLastWin32Error());

                return IntPtr.Zero;
            }

            Marshal.FreeHGlobal(bufferCode);

            if (Environment.Is64BitOperatingSystem)
            {
                Console.WriteLine("[*] PEB @ 0x{0}.", peb.ToString("X16"));
            }
            else
            {
                Console.WriteLine("[*] PEB @ 0x{0}.", peb.ToString("X8"));
            }

            if (Environment.Is64BitOperatingSystem)
            {
                pLdr = Marshal.ReadIntPtr(new IntPtr(peb.ToInt64() + 0x18));
            }
            else
            {
                pLdr = Marshal.ReadIntPtr(new IntPtr(peb.ToInt64() + 0x0C));
            }

            ldr = (PEB_LDR_DATA)Marshal.PtrToStructure(
                    pLdr,
                    typeof(PEB_LDR_DATA));
            pLdrDataTableEntry = ldr.InLoadOrderModuleList.Flink;
            entries.Add(pLdrDataTableEntry);

            while (true)
            {
                ldrDataTableEntry = (LDR_DATA_TABLE_ENTRY)Marshal.PtrToStructure(
                    pLdrDataTableEntry,
                    typeof(LDR_DATA_TABLE_ENTRY));
                pLdrDataTableEntry = ldrDataTableEntry.InLoadOrderLinks.Flink;

                if (string.Compare(
                    ldrDataTableEntry.BaseDllName.ToString(),
                    "ntdll.dll",
                    StringComparison.OrdinalIgnoreCase) == 0)
                {
                    return ldrDataTableEntry.DllBase;
                }

                if (entries.Contains(pLdrDataTableEntry))
                    break;
                else
                    entries.Add(pLdrDataTableEntry);
            }

            return IntPtr.Zero;
        }
    }
}
