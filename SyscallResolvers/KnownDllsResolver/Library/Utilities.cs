﻿using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace KnownDllsResolver.Library
{
    internal class Utilities
    {
        public static Dictionary<string, int> GetSyscallTableFromMappedSection(IntPtr pMappedSection)
        {
            var syscallTable = new Dictionary<string, int>();

            do
            {
                IntPtr pExportDirectory;
                IntPtr pModuleName;
                IntPtr pExportBase;
                IntPtr pExportName;
                string exportName;
                string moduleName;
                uint nExportTableOffset;
                ushort nOrdinal;
                uint nName;
                uint nNumberOfNames;
                uint nAddressOfFunctions;
                uint nAddressOfNames;
                uint nAddressOfNameOrdinals;
                string arch = Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE");
                var e_lfanew = Marshal.ReadInt32(pMappedSection, 0x3C);

                if (Marshal.ReadInt16(pMappedSection) != 0x5A4D)
                    break;

                if (Environment.Is64BitProcess)
                {
                    nExportTableOffset = (uint)Marshal.ReadInt32(pMappedSection, e_lfanew + 0x88);
                    pExportDirectory = new IntPtr(pMappedSection.ToInt64() + nExportTableOffset);
                }
                else
                {
                    nExportTableOffset = (uint)Marshal.ReadInt32(pMappedSection, e_lfanew + 0x78);
                    pExportDirectory = new IntPtr(pMappedSection.ToInt32() + (int)nExportTableOffset);
                }

                if (nExportTableOffset == 0)
                    break;

                nName = (uint)Marshal.ReadInt32(pExportDirectory, 0xC);
                nNumberOfNames = (uint)Marshal.ReadInt32(pExportDirectory, 0x18);
                nAddressOfFunctions = (uint)Marshal.ReadInt32(pExportDirectory, 0x1C);
                nAddressOfNames = (uint)Marshal.ReadInt32(pExportDirectory, 0x20);
                nAddressOfNameOrdinals = (uint)Marshal.ReadInt32(pExportDirectory, 0x24);

                if (Environment.Is64BitProcess)
                    pModuleName = new IntPtr(pMappedSection.ToInt64() + nName);
                else
                    pModuleName = new IntPtr(pMappedSection.ToInt32() + (int)nName);

                moduleName = Marshal.PtrToStringAnsi(pModuleName);

                if (!Regex.IsMatch(moduleName, @"^(ntdll|win32u)\.dll$", RegexOptions.IgnoreCase))
                    break;

                for (var idx = 0u; idx < nNumberOfNames; idx++)
                {
                    uint nExportOffset;
                    var nExportNameOffset = (uint)Marshal.ReadInt32(pMappedSection, (int)(nAddressOfNames + (4 * idx)));

                    if (Environment.Is64BitProcess)
                        pExportName = new IntPtr(pMappedSection.ToInt64() + nExportNameOffset);
                    else
                        pExportName = new IntPtr(pMappedSection.ToInt32() + (int)nExportNameOffset);

                    exportName = Marshal.PtrToStringAnsi(pExportName);

                    if (!exportName.StartsWith("Nt"))
                        continue;

                    nOrdinal = (ushort)Marshal.ReadInt16(pMappedSection, (int)(nAddressOfNameOrdinals + (2 * idx)));
                    nExportOffset = (uint)Marshal.ReadInt32(pMappedSection, (int)(nAddressOfFunctions + (nOrdinal * 4)));

                    if (Environment.Is64BitProcess)
                        pExportBase = new IntPtr(pMappedSection.ToInt64() + nExportOffset);
                    else
                        pExportBase = new IntPtr(pMappedSection.ToInt32() + (int)nExportOffset);

                    for (var oft = 0; oft < 0x20;)
                    {
                        if (string.Compare(arch, "x86", true) == 0)
                        {
                            if (Marshal.ReadByte(pExportBase, oft) == 0xB8) // mov eax, 0x????
                            {
                                syscallTable.Add(exportName, Marshal.ReadInt32(pExportBase, oft + 1));
                                break;
                            }

                            oft++;
                        }
                        else if (string.Compare(arch, "AMD64", true) == 0)
                        {
                            if ((uint)Marshal.ReadInt32(pExportBase, oft) == 0xB8D18B4C) // r10, rcx; mov eax, 0x????
                            {
                                syscallTable.Add(exportName, Marshal.ReadInt32(pExportBase, oft + 4));
                                break;
                            }

                            oft++;
                        }
                        else if (string.Compare(arch, "ARM64", true) == 0)
                        {
                            var opCode = (uint)Marshal.ReadInt32(pExportBase, oft);

                            if ((opCode & 0xFFE0001F) == 0xD4000001) // svc #0x??
                            {
                                syscallTable.Add(exportName, ((int)opCode >> 5) & 0x0000FFFF);
                                break;
                            }

                            oft += 4;
                        }
                        else
                        {
                            break;
                        }
                    }
                }
            } while (false);

            return syscallTable;
        }
    }
}
