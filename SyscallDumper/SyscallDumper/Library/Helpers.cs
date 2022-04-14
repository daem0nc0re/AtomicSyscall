using System.Collections.Generic;
using System.Text;

namespace SyscallDumper.Library
{
    class Helpers
    {
        public static string BuildModifiedSyscallTableText(
            Dictionary<string, int> syscallTableBase,
            Dictionary<string, int> syscallTableModified)
        {
            var result = new StringBuilder();
            var columnName = "Syscall Name";
            var columnNumber = "Number";
            var columnHexNumber = "Number (hex)";
            string formatter;
            string delimiter;
            string numberString;
            string hexNumberString;
            var maxNameLength = columnName.Length;
            var maxNumberLength = columnNumber.Length;
            var maxHexNumberLength = columnHexNumber.Length;

            foreach (var name in syscallTableModified.Keys)
            {
                numberString = string.Format(
                    "{0} -> {1}",
                    syscallTableBase[name],
                    syscallTableModified[name]);

                hexNumberString = string.Format(
                    "0x{0} -> 0x{1}",
                    syscallTableBase[name].ToString("X4"),
                    syscallTableModified[name].ToString("X4"));

                if (name.Length > maxNameLength)
                    maxNameLength = name.Length;

                if (numberString.Length > maxNumberLength)
                    maxNumberLength = numberString.Length;

                if (hexNumberString.Length > maxHexNumberLength)
                    maxHexNumberLength = hexNumberString.Length;
            }

            formatter = string.Format(
                "| {{0, -{0}}} | {{1, -{1}}} | {{2, -{2}}} |\n",
                maxNameLength,
                maxNumberLength,
                maxHexNumberLength);
            delimiter = string.Format(
                "{0}\n",
                new string('-', 10+ maxNameLength + maxNumberLength + maxHexNumberLength));

            result.Append(delimiter);
            result.Append(string.Format(
                formatter,
                columnName,
                columnNumber,
                columnHexNumber));
            result.Append(delimiter);

            foreach (var name in syscallTableModified.Keys)
            {
                numberString = string.Format(
                    "{0} -> {1}",
                    syscallTableBase[name],
                    syscallTableModified[name]);
                hexNumberString = string.Format(
                    "0x{0} -> 0x{1}",
                    syscallTableBase[name].ToString("X4"),
                    syscallTableModified[name].ToString("X4"));

                result.Append(string.Format(
                    formatter,
                    name,
                    numberString,
                    hexNumberString));
            }

            result.Append(delimiter);

            return result.ToString();
        }


        public static string BuildSyscallTableText(
            Dictionary<string, int> syscallTable)
        {
            var result = new StringBuilder();
            var columnName = "Syscall Name";
            var columnNumber = "Number";
            var columnHexNumber = "Number (hex)";
            string formatter;
            string delimiter;
            string numberString;
            string hexNumberString;
            var maxNameLength = columnName.Length;
            var maxNumberLength = columnNumber.Length;
            var maxHexNumberLength = columnHexNumber.Length;

            foreach (var name in syscallTable.Keys)
            {
                numberString = string.Format(
                    "{0}",
                    syscallTable[name]);

                hexNumberString = string.Format(
                    "0x{0}",
                    syscallTable[name].ToString("X4"));

                if (name.Length > maxNameLength)
                    maxNameLength = name.Length;

                if (numberString.Length > maxNumberLength)
                    maxNumberLength = numberString.Length;

                if (hexNumberString.Length > maxHexNumberLength)
                    maxHexNumberLength = hexNumberString.Length;
            }

            formatter = string.Format(
                "| {{0, -{0}}} | {{1, -{1}}} | {{2, -{2}}} |\n",
                maxNameLength,
                maxNumberLength,
                maxHexNumberLength);
            delimiter = string.Format(
                "{0}\n",
                new string('-', 10 + maxNameLength + maxNumberLength + maxHexNumberLength));

            result.Append(delimiter);
            result.Append(string.Format(
                formatter,
                columnName,
                columnNumber,
                columnHexNumber));
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
