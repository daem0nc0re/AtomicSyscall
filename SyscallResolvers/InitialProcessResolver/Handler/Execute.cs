using System;
using InitialProcessResolver.Library;

namespace InitialProcessResolver.Handler
{
    internal class Execute
    {
        public static void Run(CommandLineParser options)
        {
            if (options.GetFlag("help"))
            {
                options.GetHelp();

                return;
            }

            Console.WriteLine();

            if (!string.IsNullOrEmpty(options.GetValue("name")))
            {
                Modules.ResolveSyscallNumber(options.GetValue("name"), options.GetFlag("debug"));
            }
            else
            {
                Console.WriteLine("[-] No options are specified. See help message with -h option.");
            }

            Console.WriteLine();
        }
    }
}
