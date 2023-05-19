using System;
using HellsGateResolver.Handler;

namespace HellsGateResolver
{
    class HellsGateResolver
    {
        static void Main(string[] args)
        {
            var options = new CommandLineParser();

            try
            {
                options.SetTitle("HellsGateResolver - Tool to resolve syscall number with Hell's Gate techniques.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddParameter(true, "n", "name", null, "Specifies syscall name to resolve.");
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
