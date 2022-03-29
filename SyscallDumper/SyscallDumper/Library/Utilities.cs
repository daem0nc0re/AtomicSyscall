using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;

namespace SyscallDumper.Library
{
    class Utilities
    {
        public static Dictionary<string, int> DumpSyscallNumber(
            string filePath)
        {
            var results = new Dictionary<string, int>();
            var rgx = new Regex(@"^Nt\S+$");
            var fullPath = Path.GetFullPath(filePath);
            IntPtr[] offsets;
            PeLoader pe;
            string arch;
            string imageName;
            Dictionary<string, IntPtr> exports;

            if (!File.Exists(fullPath))
            {
                Console.WriteLine("[-] {0} does not exists.", fullPath);

                return results;
            }

            Console.WriteLine("[>] Loading {0}.", fullPath);

            try
            {
                pe = new PeLoader(fullPath);
            }
            catch (InvalidDataException ex)
            {
                Console.WriteLine("[!] {0}\n", ex.Message);

                return results;
            }

            arch = pe.GetArchitecture();
            imageName = pe.GetExportImageName();

            Console.WriteLine("[+] {0} is loaded successfully.", fullPath);
            Console.WriteLine("    |-> Architecture : {0}", arch);
            Console.WriteLine("    |-> Image Name   : {0}", imageName);

            if (imageName != "ntdll.dll" && imageName != "win32u.dll")
            {
                Console.WriteLine("[-] Loaded file is not ntdll.dll or win32u.dll.");
                pe.Dispose();

                return results;
            }

            exports = pe.GetExports();

            foreach (var entry in exports)
            {
                if (!rgx.IsMatch(entry.Key))
                    continue;

                if (arch == "x64")
                {
                    if (pe.SearchBytes(
                        entry.Value,
                        0x20,
                        new byte[] { 0x0F, 0x05 }).Length > 0) // syscall
                    {
                        offsets = pe.SearchBytes(
                            entry.Value,
                            0x8,
                            new byte[] { 0xB8 }); // mov eax, 0x????????

                        if (offsets.Length > 0)
                        {
                            results.Add(entry.Key, pe.ReadInt32(offsets[0], 1));
                        }
                    }
                }
                else if (arch == "x86")
                {
                    if (pe.SearchBytes(
                        entry.Value,
                        0x20,
                        new byte[] { 0x0F, 0x34 }).Length > 0) // sysenter
                    {
                        offsets = pe.SearchBytes(
                            entry.Value,
                            0x8,
                            new byte[] { 0xB8 });  // mov eax, 0x????????

                        if (offsets.Length > 0)
                        {
                            results.Add(entry.Key, pe.ReadInt32(offsets[0], 1));
                        }
                    }
                }
            }

            pe.Dispose();

            if (results.Count > 0)
            {
                Console.WriteLine("[+] Got {0} syscall(s).", results.Count);
            }
            else
            {
                Console.WriteLine("[-] No syscall.");
            }

            return results;
        }
    }
}
