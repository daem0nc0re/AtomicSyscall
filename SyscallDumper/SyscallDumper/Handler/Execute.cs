using System;
using System.IO;
using SyscallDumper.Library;

namespace SyscallDumper.Handler
{
    class Execute
    {
        public static void Run(CommandLineParser options)
        {
            string target_1 = options.GetValue("INPUT_DLL_1");
            string target_2 = options.GetValue("INPUT_DLL_2");
            string output = null;
            string result;
            string ntdll;
            string win32u;

            if (options.GetFlag("help"))
            {
                options.GetHelp();

                return;
            }

            Console.WriteLine();

            if (!string.IsNullOrEmpty(options.GetValue("output")))
            {
                output = Path.GetFullPath(options.GetValue("output"));

                if (File.Exists(output))
                {
                    Console.WriteLine("[!] {0} already exists.", output);

                    return;
                }
            }

            if (options.GetFlag("dump"))
            {
                if (string.IsNullOrEmpty(target_1))
                {
                    Console.WriteLine("[*] No target is specified.");
                    Console.WriteLine("[>] Dumping from system default ntdll.dll and win32u.dll.");

                    ntdll = Modules.GetSyscallTable(
                        @"C:\Windows\System32\ntdll.dll",
                        options.GetValue("filter"));
                    win32u = Modules.GetSyscallTable(
                        @"C:\Windows\System32\win32u.dll",
                        options.GetValue("filter"));

                    if (string.IsNullOrEmpty(output))
                    {
                        Console.WriteLine("\n{0}\n\n{1}\n", ntdll, win32u);
                    }
                    else
                    {
                        Console.WriteLine("[>] Trying to save results.");
                        Console.WriteLine("    |-> Output File Path : {0}", output);

                        try
                        {
                            File.AppendAllText(
                                output,
                                string.Format("{0}\n\n{1}", ntdll, win32u));
                        }
                        catch
                        {
                            Console.WriteLine("[-] Failed to save results.");

                            return;
                        }

                        Console.WriteLine("[+] Results are saved successfully.");
                    }
                }
                else
                {
                    result = Modules.GetSyscallTable(
                        target_1,
                        options.GetValue("filter"));

                    if (string.IsNullOrEmpty(output))
                    {
                        Console.WriteLine("\n{0}\n", result);
                    }
                    else
                    {
                        Console.WriteLine("[>] Trying to save results.");
                        Console.WriteLine("    |-> Output File Path : {0}", output);

                        try
                        {
                            File.AppendAllText(
                                output,
                                string.Format("{0}", result));
                        }
                        catch
                        {
                            Console.WriteLine("[-] Failed to save results.");

                            return;
                        }

                        Console.WriteLine("[+] Results are saved successfully.");
                    }
                }
            }
            else if (options.GetFlag("diff"))
            {
                if (string.IsNullOrEmpty(target_1))
                {
                    Console.WriteLine("[-] Missing input file path.");

                    return;
                }
                else if (string.IsNullOrEmpty(target_2))
                {
                    Console.WriteLine("[-] Missing new file path.");

                    return;
                }

                result = Modules.GetDiffTable(
                    target_1,
                    target_2,
                    options.GetValue("filter"));

                if (string.IsNullOrEmpty(output))
                {
                    Console.WriteLine("\n{0}\n", result);
                }
                else
                {
                    Console.WriteLine("[>] Trying to save results.");
                    Console.WriteLine("    |-> Output File Path : {0}", output);

                    try
                    {
                        File.AppendAllText(
                            output,
                            string.Format("{0}", result));
                    }
                    catch
                    {
                        Console.WriteLine("[-] Failed to save results.");

                        return;
                    }

                    Console.WriteLine("[+] Results are saved successfully.");
                }
            }
            else
            {
                options.GetHelp();
                Console.WriteLine("\n[!] Should be specified -d or -D option.\n");
            }
        }
    }
}
