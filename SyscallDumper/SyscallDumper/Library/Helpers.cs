using System.Collections.Generic;
using System.Text;

namespace SyscallDumper.Library
{
    class Helpers
    {
        public static string BuildSyscallTableText(
            Dictionary<string, int> syscallTable)
        {
            var result = new StringBuilder();
            string formatter;
            string delimiter;
            var maxLength = 16;

            foreach (var name in syscallTable.Keys)
            {
                if (name.Length > maxLength)
                    maxLength = name.Length;
            }

            formatter = string.Format(
                "| {{0, -{0}}} | {{1, -6}} | {{2, -12}} |\n",
                maxLength);
            delimiter = string.Format("{0}\n", new string('-', 10 + 18 + maxLength));

            result.Append(delimiter);
            result.Append(string.Format(
                formatter,
                "Syscall Name",
                "Number",
                "Number (hex)"));
            result.Append(delimiter);

            foreach (var entry in syscallTable)
            {
                result.Append(string.Format(
                    formatter,
                    entry.Key,
                    entry.Value,
                    string.Format("0x{0}", entry.Value.ToString("X4"))));
            }

            result.Append(delimiter);

            return result.ToString();
        }
    }
}
