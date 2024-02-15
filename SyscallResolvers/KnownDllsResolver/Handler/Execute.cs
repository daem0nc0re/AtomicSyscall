using System;
using KnownDllsResolver.Library;

namespace KnownDllsResolver.Handler
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
                Modules.ResolveSyscallNumber(options.GetValue("name"));
            }
            else
            {
                Console.WriteLine("[-] No options are specified.");
            }

            Console.WriteLine();
        }
    }
}
