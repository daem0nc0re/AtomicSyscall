using System;
using System.Collections.Generic;
using SyscallDumper.Handler;

namespace SyscallDumper
{
    class SyscallDumper
    {
        static void Main(string[] args)
        {
            CommandLineParser options = new CommandLineParser();
            var exclusive = new List<string> { "dump", "diff" };

            try
            {
                options.SetTitle("SyscallDumper - Tool to dump syscall.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddFlag(false, "d", "dump", "Flag to dump syscall from ntdll.dll or win32u.dll.");
                options.AddFlag(false, "D", "diff", "Flag to take diff between 2 dlls.");
                options.AddParameter(false, "f", "filter", null, "Specifies search filter (e.g. \"-f createfile\").");
                options.AddParameter(false, "o", "output", null, "Specifies output file (e.g. \"-o result.txt\").");
                options.AddArgument(false, "INPUT_DLL_1", "Specifies path of ntdll.dll or win32u.dll. Older one in diffing.");
                options.AddArgument(false, "INPUT_DLL_2", "Specifies path of ntdll.dll or win32u.dll. Newer one in diffing.");
                options.AddExclusive(exclusive);
                options.Parse(args);
                Execute.Run(options);
            }
            catch (InvalidOperationException ex)
            {
                Console.WriteLine(ex.Message);

                return;
            }
            catch (ArgumentException ex)
            {
                options.GetHelp();
                Console.WriteLine(ex.Message);

                return;
            }
        }
    }
}
