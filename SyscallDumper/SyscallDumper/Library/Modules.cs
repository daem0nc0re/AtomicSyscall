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
            var filtered = new Dictionary<string, int>();

            foreach (var entry in syscallTable)
            {
                if (entry.Key.IndexOf(filter, StringComparison.OrdinalIgnoreCase) >= 0)
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

            result.AppendFormat("[Syscall Table from {0}]\n\n", fullPath);
            
            if (table.Count > 0)
            {
                if (string.Compare(format, "c", true) == 0)
                {
                    if (string.Compare(moduleName, "ntdll.dll", true) == 0)
                        result.Append(Helpers.BuildSyscallTableAsC(table, "NT_SYSCALLS"));
                    else if (string.Compare(moduleName, "win32u.dll", true) == 0)
                        result.Append(Helpers.BuildSyscallTableAsC(table, "WIN32K_SYSCALLS"));
                    else
                        result.Append(Helpers.BuildSyscallTableAsC(table, "SYSCALLS"));
                }
                else if (string.Compare(format, "cs", true) == 0)
                {
                    if (string.Compare(moduleName, "ntdll.dll", true) == 0)
                        result.Append(Helpers.BuildSyscallTableAsCSharp(table, "NT_SYSCALLS"));
                    else if (string.Compare(moduleName, "win32u.dll", true) == 0)
                        result.Append(Helpers.BuildSyscallTableAsCSharp(table, "WIN32K_SYSCALLS"));
                    else
                        result.Append(Helpers.BuildSyscallTableAsCSharp(table, "SYSCALLS"));
                }
                else if (string.Compare(format, "py", true) == 0)
                {
                    if (string.Compare(moduleName, "ntdll.dll", true) == 0)
                        result.Append(Helpers.BuildSyscallTableAsPython(table, "g_NtSyscalls"));
                    else if (string.Compare(moduleName, "win32u.dll", true) == 0)
                        result.Append(Helpers.BuildSyscallTableAsPython(table, "g_Win32kSyscalls"));
                    else
                        result.Append(Helpers.BuildSyscallTableAsPython(table, "g_Syscalls"));
                }
                else
                {
                    result.Append(Helpers.BuildSyscallTableDefault(table));
                }
            }

            result.AppendFormat("\n[*] Found {0} syscall(s).\n", table.Count);

            if (!string.IsNullOrEmpty(filter))
                result.AppendFormat("[*] Filter String : \"{0}\"\n", filter);
            
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

            if (string.Compare(oldModule, newModule, true) != 0)
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
                results.AppendFormat("\n[*] Deleted {0} syscall(s).\n", deleted.Count);
            }

            if (modified.Count > 0)
            {
                if (results.Length != 0)
                    results.Append("\n\n");

                results.Append("################################################\n");
                results.Append("#               MODIFIED SYSCALLS              #\n");
                results.Append("################################################\n\n");;
                results.Append(Helpers.BuildModifiedSyscallTableText(oldTable, modified));
                results.AppendFormat("\n[*] Modified {0} syscall(s).\n", modified.Count);
            }

            if (added.Count > 0)
            {
                if (results.Length != 0)
                    results.Append("\n\n");

                results.Append("################################################\n");
                results.Append("#                 NEW SYSCALLS                 #\n");
                results.Append("################################################\n\n");
                results.Append(Helpers.BuildSyscallTableDefault(added));
                results.AppendFormat("\n[*] Added {0} syscall(s).\n", added.Count);
            }

            if (!string.IsNullOrEmpty(filter))
                results.AppendFormat("[*] Filter String : \"{0}\"\n", filter);

            return results.ToString();
        }
    }
}
