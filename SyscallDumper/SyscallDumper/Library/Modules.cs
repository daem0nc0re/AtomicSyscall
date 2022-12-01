using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace SyscallDumper.Library
{
    internal class Modules
    {
        /*
         * private functions
         */
        private static Dictionary<string, int> FilterTable(
            Dictionary<string, int> syscallTable,
            string filter)
        {
            var comparison = StringComparison.OrdinalIgnoreCase;
            var filtered = new Dictionary<string, int>();

            foreach (var entry in syscallTable)
            {
                if (entry.Key.IndexOf(filter, comparison) >= 0)
                    filtered.Add(entry.Key, entry.Value);
            }

            return filtered;
        }


        private static Dictionary<string, int> LookupSyscallNumber(
            Dictionary<string, int> syscallTable,
            int syscallNumber)
        {
            var filtered = new Dictionary<string, int>();

            foreach (var entry in syscallTable)
            {
                if (entry.Value == syscallNumber)
                    filtered.Add(entry.Key, entry.Value);
            }

            return filtered;
        }


        /*
         * public functions
         */
        public static string GetSyscallTable(string filePath, string filter, int syscallNumber, string format)
        {
            Dictionary<string, int> table;
            var result = new StringBuilder();
            var fullPath = Path.GetFullPath(filePath);

            if (!File.Exists(fullPath))
            {
                Console.WriteLine("[-] {0} does not exists.", fullPath);

                return null;
            }

            table = Utilities.DumpSyscallNumber(fullPath, out string moduleName);

            if (!string.IsNullOrEmpty(filter))
                table = FilterTable(table, filter);

            if (syscallNumber >= 0)
                table = LookupSyscallNumber(table, syscallNumber);

            result.Append(string.Format("[Syscall Table from {0}]\n\n", fullPath));
            
            if (table.Count > 0)
            {
                if (Helpers.CompareIgnoreCase(format, "c"))
                {
                    if (Helpers.CompareIgnoreCase(moduleName, "ntdll.dll"))
                        result.Append(Helpers.BuildSyscallTableAsC(table, "NT_SYSCALLS"));
                    else if (Helpers.CompareIgnoreCase(moduleName, "win32u.dll"))
                        result.Append(Helpers.BuildSyscallTableAsC(table, "NTGDI_SYSCALLS"));
                    else
                        result.Append(Helpers.BuildSyscallTableAsC(table, "SYSCALLS"));
                }
                else if (Helpers.CompareIgnoreCase(format, "cs"))
                {
                    if (Helpers.CompareIgnoreCase(moduleName, "ntdll.dll"))
                        result.Append(Helpers.BuildSyscallTableAsCSharp(table, "NT_SYSCALLS"));
                    else if (Helpers.CompareIgnoreCase(moduleName, "win32u.dll"))
                        result.Append(Helpers.BuildSyscallTableAsCSharp(table, "NTGDI_SYSCALLS"));
                    else
                        result.Append(Helpers.BuildSyscallTableAsCSharp(table, "SYSCALLS"));
                }
                else if (Helpers.CompareIgnoreCase(format, "py"))
                {
                    if (Helpers.CompareIgnoreCase(moduleName, "ntdll.dll"))
                        result.Append(Helpers.BuildSyscallTableAsPython(table, "g_NtSyscalls"));
                    else if (Helpers.CompareIgnoreCase(moduleName, "win32u.dll"))
                        result.Append(Helpers.BuildSyscallTableAsPython(table, "g_NtGdiSyscalls"));
                    else
                        result.Append(Helpers.BuildSyscallTableAsPython(table, "g_Syscalls"));
                }
                else
                {
                    result.Append(Helpers.BuildSyscallTableDefault(table));
                }
            }

            result.Append(string.Format("\n[*] Found {0} syscall(s).\n", table.Count));

            if (!string.IsNullOrEmpty(filter))
                result.Append(string.Format("[*] Filter String : \"{0}\"\n", filter));
            
            return result.ToString();
        }


        public static string GetDiffTable(string oldFilePath, string newFilePath, string filter)
        {
            Dictionary<string, int> oldTable;
            Dictionary<string, int> newTable;
            var results = new StringBuilder();
            var deleted = new Dictionary<string, int>();
            var modified = new Dictionary<string, int>();
            var added = new Dictionary<string, int>();

            if (string.IsNullOrEmpty(oldFilePath) || string.IsNullOrEmpty(newFilePath))
            {
                Console.WriteLine("[-] Missing file name to diff.");

                return null;
            }

            oldFilePath = Path.GetFullPath(oldFilePath);
            newFilePath = Path.GetFullPath(newFilePath);

            if (!File.Exists(oldFilePath))
            {
                Console.WriteLine("[-] {0} does not exist.", oldFilePath);

                return null;
            }
            else if (!File.Exists(newFilePath))
            {
                Console.WriteLine("[-] {0} does not exist.", newFilePath);

                return null;
            }

            Console.WriteLine("[>] Trying to take diff.");
            Console.WriteLine("    [*] Old File : {0}", oldFilePath);
            Console.WriteLine("    [*] New File : {0}", newFilePath);

            oldTable = Utilities.DumpSyscallNumber(oldFilePath, out string oldModule);
            newTable = Utilities.DumpSyscallNumber(newFilePath, out string newModule);

            if (!Helpers.CompareIgnoreCase(oldModule, newModule))
            {
                Console.WriteLine("[-] Module names don't match.");

                return null;
            }

            if (!string.IsNullOrEmpty(filter))
            {
                oldTable = FilterTable(oldTable, filter);
                newTable = FilterTable(newTable, filter);
            }

            foreach (var entry in oldTable)
            {
                if (newTable.ContainsKey(entry.Key))
                {
                    if (newTable[entry.Key] != entry.Value)
                        modified.Add(entry.Key, newTable[entry.Key]);
                }
                else
                {
                    deleted.Add(entry.Key, entry.Value);
                }
            }

            foreach (var entry in newTable)
            {
                if (!oldTable.ContainsKey(entry.Key))
                    added.Add(entry.Key, entry.Value);
            }

            if (deleted.Count > 0)
            {
                results.Append("################################################\n");
                results.Append("#               DELETED SYSCALLS               #\n");
                results.Append("################################################\n\n");
                results.Append(Helpers.BuildSyscallTableDefault(deleted));
                results.Append(string.Format("\n[*] Deleted {0} syscall(s).\n", deleted.Count));
            }

            if (modified.Count > 0)
            {
                if (results.Length != 0)
                    results.Append("\n\n");

                results.Append("################################################\n");
                results.Append("#               MODIFIED SYSCALLS              #\n");
                results.Append("################################################\n\n");;
                results.Append(Helpers.BuildModifiedSyscallTableText(oldTable, modified));
                results.Append(string.Format("\n[*] Modified {0} syscall(s).\n", modified.Count));
            }

            if (added.Count > 0)
            {
                if (results.Length != 0)
                    results.Append("\n\n");

                results.Append("################################################\n");
                results.Append("#                 NEW SYSCALLS                 #\n");
                results.Append("################################################\n\n");
                results.Append(Helpers.BuildSyscallTableDefault(added));
                results.Append(string.Format("\n[*] Added {0} syscall(s).\n", added.Count));
            }

            if (!string.IsNullOrEmpty(filter))
                results.Append(string.Format("[*] Filter String : \"{0}\"\n", filter));

            return results.ToString();
        }
    }
}
