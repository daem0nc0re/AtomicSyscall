using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;

namespace SyscallDumper.Library
{
    internal class Utilities
    {
        public static Dictionary<string, int> DumpSyscallNumber(string filePath, out string moduleName)
        {
            Dictionary<string, IntPtr> exports;
            var results = new Dictionary<string, int>();
            var fullPath = Path.GetFullPath(filePath);
            moduleName = null;

            if (!File.Exists(fullPath))
            {
                Console.WriteLine("[-] {0} does not exists.", fullPath);
                return results;
            }

            try
            {
                Console.WriteLine("[>] Loading {0}.", fullPath);

                using (var pe = new PeFile(fullPath))
                {
                    moduleName = pe.GetExportImageName();

                    Console.WriteLine("[+] {0} is loaded successfully.", fullPath);
                    Console.WriteLine("    [*] Architecture : {0}", pe.Architecture);
                    Console.WriteLine("    [*] Image Name   : {0}", moduleName);

                    if (!Regex.IsMatch(moduleName, @"^(ntdll|win32u)\.dll$", RegexOptions.IgnoreCase))
                    {
                        Console.WriteLine("[-] Loaded file is not ntdll.dll or win32u.dll.");
                        return results;
                    }

                    exports = pe.GetExports();

                    foreach (var entry in exports)
                    {
                        if (!entry.Key.StartsWith("Nt"))
                            continue;

                        if (pe.Architecture == PeFile.IMAGE_FILE_MACHINE.I386)
                        {
                            if (pe.ReadByte(entry.Value) == 0xB8) // mov eax, 0x????
                                results.Add(entry.Key, pe.ReadInt32(entry.Value, 1));
                        }
                        else if (pe.Architecture == PeFile.IMAGE_FILE_MACHINE.AMD64)
                        {
                            if (pe.SearchBytes(entry.Value, 0x20, new byte[] { 0x0F, 0x05 }).Length > 0) // syscall
                            {
                                if ((uint)pe.ReadInt32(entry.Value) == 0xB8D18B4C) // mov r10, rcx; mov eax, 0x???? 
                                    results.Add(entry.Key, pe.ReadInt32(entry.Value, 4));
                            }
                        }
                        else if (pe.Architecture == PeFile.IMAGE_FILE_MACHINE.ARM64)
                        {
                            if (((uint)pe.ReadInt32(entry.Value) & 0xFFE0001F) == 0xD4000001) // svc #0x????
                                results.Add(entry.Key, (pe.ReadInt32(entry.Value) >> 5) & 0x0000FFFF); // Decode svc instruction
                        }
                        else
                        {
                            throw new InvalidDataException("Unsupported architecture.");
                        }
                    }
                }

                if (results.Count > 0)
                    Console.WriteLine("[+] Got {0} syscall(s).", results.Count);
                else
                    Console.WriteLine("[-] No syscall.");
            }
            catch (InvalidDataException ex)
            {
                Console.WriteLine("[!] {0}\n", ex.Message);
            }

            return results;
        }
    }
}
