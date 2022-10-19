using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace HellsGatePoC.Library
{
    internal class HellsGate
    {
        /*
         * Definisions for PE header
         */
        private enum DllCharacteristicsType : ushort
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

        private enum IMAGE_FILE_MACHINE : ushort
        {
            UNKNOWN = 0,
            I386 = 0x014C,
            R3000BE = 0x0160,
            R3000LE = 0x0162,
            R4000 = 0x0166,
            R10000 = 0x0168,
            WCEMIPSV2 = 0x0169,
            ALPHA = 0x0184,
            SH3 = 0x01A2,
            SH3DSP = 0x01A3,
            SH3E = 0x01A4,
            SH4 = 0x01A6,
            SH5 = 0x01A8,
            ARM = 0x01C0,
            THUMB = 0x01C2,
            ARM2 = 0x01C4,
            AM33 = 0x01D3,
            POWERPC = 0x01F0,
            POWERPCFP = 0x01F1,
            IA64 = 0x0200,
            MIPS16 = 0x0266,
            ALPHA64 = 0x0284,
            MIPSFPU = 0x0366,
            MIPSFPU16 = 0x0466,
            AXP64 = 0x0284,
            TRICORE = 0x0520,
            CEF = 0x0CEF,
            EBC = 0x0EBC,
            AMD64 = 0x8664,
            M32R = 0x9041,
            ARM64 = 0xAA64,
            CEE = 0xC0EE
        }

        private enum MagicType : ushort
        {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b,
            IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
        }

        private enum SubSystemType : ushort
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
        private struct IMAGE_DATA_DIRECTORY
        {
            public uint VirtualAddress;
            public uint Size;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IMAGE_DOS_HEADER
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
        private struct IMAGE_EXPORT_DIRECTORY
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
        private struct IMAGE_FILE_HEADER
        {
            public IMAGE_FILE_MACHINE Machine;
            public ushort NumberOfSections;
            public uint TimeDateStamp;
            public uint PointerToSymbolTable;
            public uint NumberOfSymbols;
            public ushort SizeOfOptionalHeader;
            public ushort Characteristics;
        }

        [StructLayout(LayoutKind.Explicit)]
        private struct IMAGE_OPTIONAL_HEADER32
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
        private struct IMAGE_OPTIONAL_HEADER64
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
        private struct IMAGE_NT_HEADERS32
        {
            public int Signature;
            public IMAGE_FILE_HEADER FileHeader;
            public IMAGE_OPTIONAL_HEADER32 OptionalHeader;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        private struct IMAGE_NT_HEADERS64
        {
            public int Signature;
            public IMAGE_FILE_HEADER FileHeader;
            public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
        }

        /*
         * Functions
         */
        public static Dictionary<string, int> DumpSyscallNumberFromNtdll()
        {
            IntPtr pNtHeader;
            IntPtr pExportDirectory;
            IntPtr pExportNames;
            IntPtr pExportOrdinals;
            IntPtr pExportFunctions;
            IntPtr pFunctionName;
            IntPtr pFunction;
            string exportName;
            short ordinal;
            string functionName;
            int syscallNumber;
            uint numNames;
            uint rvaExportDirectory;
            IMAGE_DOS_HEADER dosHeader;
            IMAGE_FILE_MACHINE arch;
            IMAGE_EXPORT_DIRECTORY exportDirectory;
            var results = new Dictionary<string, int>();
            var rgx = new Regex(@"^Nt\S+$");

            Console.WriteLine("[>] Trying to find the base address of ntdll.dll.");

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

            dosHeader = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(
                hModule,
                typeof(IMAGE_DOS_HEADER));

            if (Environment.Is64BitProcess)
                pNtHeader = new IntPtr(hModule.ToInt64() + dosHeader.e_lfanew);
            else
                pNtHeader = new IntPtr(hModule.ToInt32() + dosHeader.e_lfanew);

            arch = (IMAGE_FILE_MACHINE)Marshal.ReadInt16(pNtHeader, Marshal.SizeOf(typeof(int)));

            if (arch == IMAGE_FILE_MACHINE.I386)
            {
                Console.WriteLine("[*] Architecture is {0}.", arch.ToString());

                var ntHeader = (IMAGE_NT_HEADERS32)Marshal.PtrToStructure(
                    pNtHeader,
                    typeof(IMAGE_NT_HEADERS32));
                rvaExportDirectory = ntHeader.OptionalHeader.ExportTable.VirtualAddress;
            }
            else if (arch == IMAGE_FILE_MACHINE.AMD64)
            {
                Console.WriteLine("[*] Architecture is {0}.", arch.ToString());

                var ntHeader = (IMAGE_NT_HEADERS64)Marshal.PtrToStructure(
                    pNtHeader,
                    typeof(IMAGE_NT_HEADERS64));
                rvaExportDirectory = ntHeader.OptionalHeader.ExportTable.VirtualAddress;
            }
            else if (arch == IMAGE_FILE_MACHINE.ARM64)
            {
                Console.WriteLine("[*] Architecture is {0}.", arch.ToString());

                var ntHeader = (IMAGE_NT_HEADERS64)Marshal.PtrToStructure(
                    pNtHeader,
                    typeof(IMAGE_NT_HEADERS64));
                rvaExportDirectory = ntHeader.OptionalHeader.ExportTable.VirtualAddress;
            }
            else
            {
                Console.WriteLine("[-] Unsupported architecture is detected.");

                return results;
            }


            if (Environment.Is64BitProcess)
            {
                pExportDirectory = new IntPtr(hModule.ToInt64() + rvaExportDirectory);
                exportDirectory = (IMAGE_EXPORT_DIRECTORY)Marshal.PtrToStructure(
                    pExportDirectory,
                    typeof(IMAGE_EXPORT_DIRECTORY));
                exportName = Marshal.PtrToStringAnsi(new IntPtr(hModule.ToInt64() + exportDirectory.Name));
            }
            else
            {
                pExportDirectory = new IntPtr(hModule.ToInt32() + rvaExportDirectory);
                exportDirectory = (IMAGE_EXPORT_DIRECTORY)Marshal.PtrToStructure(
                    pExportDirectory,
                    typeof(IMAGE_EXPORT_DIRECTORY));
                exportName = Marshal.PtrToStringAnsi(new IntPtr(hModule.ToInt32() + exportDirectory.Name));
            }

            if (exportName != "ntdll.dll")
            {
                Console.WriteLine("[-] Failed to get ntdll.dll.");

                return results;
            }

            numNames = exportDirectory.NumberOfNames;

            if (Environment.Is64BitProcess)
            {
                pExportNames = new IntPtr(hModule.ToInt64() + exportDirectory.AddressOfNames);
                pExportOrdinals = new IntPtr(hModule.ToInt64() + exportDirectory.AddressOfNameOrdinals);
                pExportFunctions = new IntPtr(hModule.ToInt64() + exportDirectory.AddressOfFunctions);
            }
            else
            {
                pExportNames = new IntPtr(hModule.ToInt32() + exportDirectory.AddressOfNames);
                pExportOrdinals = new IntPtr(hModule.ToInt32() + exportDirectory.AddressOfNameOrdinals);
                pExportFunctions = new IntPtr(hModule.ToInt32() + exportDirectory.AddressOfFunctions);
            }

            for (var idx = 0; idx < numNames; idx++)
            {
                if (Environment.Is64BitProcess)
                {
                    pFunctionName = new IntPtr(
                        hModule.ToInt64() + 
                        Marshal.ReadInt32(new IntPtr(pExportNames.ToInt64() + Marshal.SizeOf(typeof(uint)) * idx)));
                    ordinal = Marshal.ReadInt16(new IntPtr(pExportOrdinals.ToInt64() + Marshal.SizeOf(typeof(short)) * idx));
                    pFunction = new IntPtr(
                        hModule.ToInt64() +
                        Marshal.ReadInt32(new IntPtr(pExportFunctions.ToInt64() + Marshal.SizeOf(typeof(uint)) * ordinal)));
                }
                else
                {
                    pFunctionName = new IntPtr(
                        hModule.ToInt32() +
                        Marshal.ReadInt32(new IntPtr(pExportNames.ToInt32() + Marshal.SizeOf(typeof(uint)) * idx)));
                    ordinal = Marshal.ReadInt16(new IntPtr(pExportOrdinals.ToInt32() + Marshal.SizeOf(typeof(short)) * idx));
                    pFunction = new IntPtr(
                        hModule.ToInt32() +
                        Marshal.ReadInt32(new IntPtr(pExportFunctions.ToInt32() + Marshal.SizeOf(typeof(uint)) * ordinal)));
                }

                functionName = Marshal.PtrToStringAnsi(pFunctionName);

                if (!rgx.IsMatch(functionName))
                    continue;

                if (arch == IMAGE_FILE_MACHINE.I386)
                {
                    if (SearchBytes(
                        pFunction,
                        0x20,
                        new byte[] { 0x0F, 0x34 }).Length > 0) // sysenter
                    {
                        if (Marshal.ReadByte(pFunction) == 0xB8) // mov eax, 0x????
                        {
                            syscallNumber = Marshal.ReadInt32(pFunction, 1);
                            results.Add(functionName, syscallNumber);
                        }
                    }
                }
                else if (arch == IMAGE_FILE_MACHINE.AMD64)
                {
                    if (SearchBytes(
                        pFunction,
                        0x20,
                        new byte[] { 0x0F, 0x05 }).Length > 0) // syscall
                    {
                        if ((uint)Marshal.ReadInt32(pFunction) == 0xB8D18B4C) // mov r10, rcx; mov eax, 0x???? 
                        {
                            syscallNumber = Marshal.ReadInt32(pFunction, 4);
                            results.Add(functionName, syscallNumber);
                        }
                    }
                }
                else if (arch == IMAGE_FILE_MACHINE.ARM64)
                {
                    if (((uint)Marshal.ReadInt32(pFunction) & 0xFFE0001F) == 0xD4000001) // svc #0x????
                    {
                        syscallNumber = (Marshal.ReadInt32(pFunction) >> 5) & 0x0000FFFF; // Decode svc instruction
                        results.Add(functionName, syscallNumber);
                    }
                }
                else
                {
                    Console.WriteLine("[-] Unsupported architecture.");

                    break;
                }
            }

            if (results.Count == 0)
                Console.WriteLine("[-] Failed to get syscall numbers.");
            else
                Console.WriteLine("[+] Got {0} syscall(s).", results.Count);

            return results;
        }


        private static IntPtr[] SearchBytes(
            IntPtr basePointer,
            int range,
            byte[] searchBytes)
        {
            IntPtr pointer;
            bool found;
            var results = new List<IntPtr>();

            for (var count = 0; count < (range - searchBytes.Length); count++)
            {
                found = false;

                if (Environment.Is64BitProcess)
                    pointer = new IntPtr(basePointer.ToInt64() + count);
                else
                    pointer = new IntPtr(basePointer.ToInt32() + count);

                for (var position = 0; position < searchBytes.Length; position++)
                {
                    found = (Marshal.ReadByte(pointer, position) == searchBytes[position]);

                    if (!found)
                        break;
                }

                if (found)
                    results.Add(pointer);
            }

            return results.ToArray();
        }


        private static IntPtr SearchNtdllBase()
        {
            ProcessModuleCollection modules = Process.GetCurrentProcess().Modules;

            foreach (ProcessModule mod in modules)
            {
                if (string.Compare(
                    Path.GetFileName(mod.FileName),
                    "ntdll.dll",
                    StringComparison.OrdinalIgnoreCase) == 0)
                {
                    return mod.BaseAddress;
                }
            }

            return IntPtr.Zero;
        }
    }
}
