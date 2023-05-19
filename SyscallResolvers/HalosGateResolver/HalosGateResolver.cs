using System;
using HalosGateResolver.Handler;

namespace HalosGateResolver
{
    class HalosGateResolver
    {
        static void Main(string[] args)
        {
            var options = new CommandLineParser();

            try
            {
                options.SetTitle("HalosGateResolver - Tool to resolve syscall number with Halo's Gate techniques.");
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
