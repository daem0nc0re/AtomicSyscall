using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace SyscallDumper.Library
{
    class Modules
    {
        private static Dictionary<string, int> FilterTable(
            Dictionary<string, int> syscallTable,
            string filter)
        {
            var filtered = new Dictionary<string, int>();

            foreach (var entry in syscallTable)
            {
                if (entry.Key.IndexOf(
                    filter,
                    StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    filtered.Add(entry.Key, entry.Value);
                }
            }

            return filtered;
        }


        public static string GetSyscallTable(
            string filePath,
            string filter)
        {
            var result = new StringBuilder();
            var fullPath = Path.GetFullPath(filePath);
            Dictionary<string, int> table;

            if (!File.Exists(fullPath))
            {
                Console.WriteLine("[-] {0} does not exists.", fullPath);

                return null;
            }

            table = Utilities.DumpSyscallNumber(fullPath);

            if (!string.IsNullOrEmpty(filter))
                table = FilterTable(table, filter);

            result.Append(string.Format("[Syscall Table from {0}]\n\n", fullPath));
            
            if (table.Count > 0)
                result.Append(Helpers.BuildSyscallTableText(table));

            result.Append(string.Format("\n[*] Found {0} syscall(s).\n", table.Count));

            if (!string.IsNullOrEmpty(filter))
                result.Append(string.Format("[*] Filter String : \"{0}\"\n", filter));
            
            return result.ToString();
        }


        public static string GetDiffTable(
            string oldFilePath,
            string newFilePath,
            string filter)
        {
            var results = new StringBuilder();
            Dictionary<string, int> oldTable;
            Dictionary<string, int> newTable;
            var deleted = new Dictionary<string, int>();
            var modified = new Dictionary<string, int>();
            var added = new Dictionary<string, int>();

            if (string.IsNullOrEmpty(oldFilePath) ||
                string.IsNullOrEmpty(newFilePath))
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
            Console.WriteLine("    |-> Old File : {0}", oldFilePath);
            Console.WriteLine("    |-> New File : {0}", newFilePath);

            oldTable = Utilities.DumpSyscallNumber(oldFilePath);
            newTable = Utilities.DumpSyscallNumber(newFilePath);

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
                results.Append(Helpers.BuildSyscallTableText(deleted));
                results.Append(string.Format(
                    "\n[*] Deleted {0} syscall(s).\n",
                    deleted.Count));
            }

            if (modified.Count > 0)
            {
                if (results.Length != 0)
                    results.Append("\n\n");

                results.Append("################################################\n");
                results.Append("#               MODIFIED SYSCALLS              #\n");
                results.Append("################################################\n\n");;
                results.Append(Helpers.BuildModifiedSyscallTableText(oldTable, modified));
                results.Append(string.Format(
                    "\n[*] Modified {0} syscall(s).\n",
                    modified.Count));
            }

            if (added.Count > 0)
            {
                if (results.Length != 0)
                    results.Append("\n\n");

                results.Append("################################################\n");
                results.Append("#                 NEW SYSCALLS                 #\n");
                results.Append("################################################\n\n");
                results.Append(Helpers.BuildSyscallTableText(added));
                results.Append(string.Format(
                    "\n[*] Added {0} syscall(s).\n",
                    added.Count));
            }

            if (!string.IsNullOrEmpty(filter))
                results.Append(string.Format("[*] Filter String : \"{0}\"\n", filter));

            return results.ToString();
        }
    }
}
