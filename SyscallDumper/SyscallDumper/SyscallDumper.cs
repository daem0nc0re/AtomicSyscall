using System;
using System.Collections.Generic;
using SyscallDumper.Handler;

namespace SyscallDumper
{
    internal class SyscallDumper
    {
        static void Main(string[] args)
        {
            var options = new CommandLineParser();
            var exclusive_1 = new List<string> { "diff", "dump" };
            var exclusive_2 = new List<string> { "number", "search" };

            try
            {
                options.SetTitle("SyscallDumper - Tool to dump syscall.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddFlag(false, "d", "dump", "Flag to dump syscall from ntdll.dll or win32u.dll.");
                options.AddFlag(false, "D", "diff", "Flag to take diff between 2 dlls.");
                options.AddParameter(false, "f", "format", null, "Specifies output format. \"c\" for C/C++, \"cs\" for CSharp, \"py\" for Python.");
                options.AddParameter(false, "n", "number", null, "Specifies syscall number to lookup in decimal or hex format.");
                options.AddParameter(false, "o", "output", null, "Specifies output file (e.g. \"-o result.txt\").");
                options.AddParameter(false, "s", "search", null, "Specifies search filter (e.g. \"-s createfile\").");
                options.AddArgument(false, "INPUT_DLL_1", "Specifies path of ntdll.dll or win32u.dll. Older one in diffing.");
                options.AddArgument(false, "INPUT_DLL_2", "Specifies path of ntdll.dll or win32u.dll. Newer one in diffing.");
                options.AddExclusive(exclusive_1);
                options.AddExclusive(exclusive_2);
                options.Parse(args);
                Execute.Run(options);
            }
            catch (InvalidOperationException ex)
            {
                Console.WriteLine(ex.Message);
            }
            catch (ArgumentException ex)
            {
                options.GetHelp();
                Console.WriteLine(ex.Message);
            }
        }
    }
}
