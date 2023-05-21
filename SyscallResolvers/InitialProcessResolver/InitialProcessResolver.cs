using System;
using InitialProcessResolver.Handler;

namespace InitialProcessResolver
{
    internal class InitialProcessResolver
    {
        static void Main(string[] args)
        {
            var options = new CommandLineParser();

            try
            {
                options.SetTitle("InitialProcessResolver - PoC to resolve syscall number with initial process technique.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddParameter(true, "n", "name", null, "Specifies syscall name.");
                options.AddFlag(false, "d", "debug", "Flag to enable debug break.");
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
