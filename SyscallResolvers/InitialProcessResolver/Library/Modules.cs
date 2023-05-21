using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using InitialProcessResolver.Interop;

namespace InitialProcessResolver.Library
{
    using NTSTATUS = Int32;

    internal class Modules
    {
        public static int ResolveSyscallNumber(string syscallName, bool debug)
        {
            bool status;
            int nSyscallNumber = -1;
            var addressFormat = Environment.Is64BitProcess ? "X16" : "X8";

            Console.WriteLine("[>] Trying to create initial process.");

            status = Utilities.CreateInitialProcess(out IntPtr hProcess, out IntPtr hThread);

            if (status)
            {
                do
                {
                    NTSTATUS ntstatus;
                    Process process;
                    IntPtr pNtdll;
                    IntPtr pDataBuffer;
                    var pSyscall = IntPtr.Zero;
                    status = Helpers.GetProcessBasicInformation(hProcess, out PROCESS_BASIC_INFORMATION pbi);

                    if (!status)
                    {
                        Console.WriteLine("[-] Failed to get process information.");
                        break;
                    }
                    else
                    {
                        try
                        {
                            process = Process.GetProcessById((int)pbi.UniqueProcessId.ToUInt64());
                        }
                        catch
                        {
                            Console.WriteLine("[-] Failed to find created process.");
                            break;
                        }

                        Console.WriteLine("[+] Initial process is created successfully.");
                        Console.WriteLine("    [*] Process Name : {0}", process.ProcessName);
                        Console.WriteLine("    [*] Process ID   : {0}", process.Id);
                    }

                    Console.WriteLine("[>] Trying to dump Nt API address.");

                    pNtdll = Helpers.GetNtdllBaseAddress();

                    if (pNtdll == IntPtr.Zero)
                    {
                        Console.WriteLine("[-] Failed to find the base address of ntdll.dll.");
                        break;
                    }
                    else
                    {
                        Console.WriteLine("[*] ntdll.dll @ 0x{0}", pNtdll.ToString(addressFormat));
                    }

                    status = Utilities.GetRemoteNtcalls(
                        hProcess,
                        pNtdll,
                        out IMAGE_FILE_MACHINE architecture,
                        out Dictionary<string, int> exports);

                    if (!status)
                    {
                        Console.WriteLine("[-] Failed to get Nt API address.");
                        break;
                    }
                    else
                    {
                        Console.WriteLine("[+] Got {0} entries (Architecure: {1}).", exports.Count, architecture.ToString());
                    }

                    foreach (var entry in exports)
                    {
                        if (Helpers.CompareIgnoreCase(entry.Key, syscallName))
                        {
                            syscallName = entry.Key;

                            if (Environment.Is64BitProcess)
                                pSyscall = new IntPtr(pNtdll.ToInt64() + entry.Value);
                            else
                                pSyscall = new IntPtr(pNtdll.ToInt32() + entry.Value);

                            break;
                        }
                    }

                    if (pSyscall == IntPtr.Zero)
                    {
                        Console.WriteLine("[-] Failed to find \"{0}\".", syscallName);
                        break;
                    }
                    else
                    {
                        Console.WriteLine("[+] {0} @ 0x{1}", syscallName, pSyscall.ToString(addressFormat));
                    }

                    pDataBuffer = Marshal.AllocHGlobal(0x30);
                    ntstatus = NativeMethods.NtReadVirtualMemory(
                        hProcess,
                        pSyscall,
                        pDataBuffer,
                        0x30u,
                        out uint _);

                    if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    {
                        Console.WriteLine("[-] Failed to read {0} API code.", syscallName);
                    }
                    else
                    {
                        if (architecture == IMAGE_FILE_MACHINE.I386)
                        {
                            if (Marshal.ReadByte(pDataBuffer) == 0xB8) // mov eax, 0x????
                            {
                                nSyscallNumber = Marshal.ReadInt32(pDataBuffer, 1);
                            }
                        }
                        else if (architecture == IMAGE_FILE_MACHINE.AMD64)
                        {
                            if (Helpers.SearchBytes(
                                pDataBuffer,
                                0x20,
                                new byte[] { 0x0F, 0x05 }).Length > 0) // syscall
                            {
                                if ((uint)Marshal.ReadInt32(pDataBuffer) == 0xB8D18B4C) // mov r10, rcx; mov eax, 0x???? 
                                {
                                    nSyscallNumber = Marshal.ReadInt32(pDataBuffer, 4);
                                }
                            }
                        }
                        else if (architecture == IMAGE_FILE_MACHINE.ARM64)
                        {
                            if (((uint)Marshal.ReadInt32(pDataBuffer) & 0xFFE0001F) == 0xD4000001) // svc #0x????
                            {
                                nSyscallNumber = (Marshal.ReadInt32(pDataBuffer) >> 5) & 0x0000FFFF; // Decode svc instruction
                            }
                        }
                        else
                        {
                            Console.WriteLine("[-] Unsupported architecture.");
                        }
                    }

                    if (nSyscallNumber == -1)
                        Console.WriteLine("[-] Failed to get syscall number for {0}.", syscallName);
                    else
                        Console.WriteLine("[+] Syscall number for {0} is {1} (0x{2}).", syscallName, nSyscallNumber, nSyscallNumber.ToString("X"));

                    Marshal.FreeHGlobal(pDataBuffer);
                } while (false);

                if (debug)
                {
                    Console.WriteLine("[*] Debug break. To exit this program, hit [ENTER] key.");
                    Console.ReadLine();
                }

                Console.WriteLine("[*] Terminate initial process.");
                NativeMethods.NtTerminateProcess(hProcess, Win32Consts.STATUS_SUCCESS);
            }
            else
            {
                Console.WriteLine("[-] Failed to create initial process.");
            }

            Console.WriteLine("[*] Done.");

            return nSyscallNumber;
        }
    }
}
