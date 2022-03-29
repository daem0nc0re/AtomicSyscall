using System;
using System.Runtime.InteropServices;
using System.Text;
using PhysicalResolvePoC.Interop;
using PhysicalResolvePoC.Library;

namespace PhysicalResolvePoC
{
    class PhysicalResolvePoC
    {
        static void Main()
        {
            Console.WriteLine("\n--[ Syscall PoC for Physical Resolve\n");

            /*
             * Syscall Number Resolve
             */
            if (!Environment.Is64BitOperatingSystem)
            {
                Console.WriteLine("[-] 32 bit OS is not supported.\n");

                return;
            }

            if (!Syscall.Initialize(PhysicalResolve.DumpSyscallNumber(
                @"C:\Windows\System32\ntdll.dll")))
            {
                Console.WriteLine("[-] Failed to dump syscall numbers.\n");

                return;
            }

            /*
             * Enumerate Drivers
             */
            int ntstatus;
            int STATUS_SUCCESS = 0;
            int STATUS_INFO_LENGTH_MISMATCH = Convert.ToInt32("0xC0000004", 16);
            int SystemInfoLength = 8;
            IntPtr SystemInfoBuffer;

            Console.WriteLine("[>] Trying to list process.");

            do
            {
                SystemInfoBuffer = Marshal.AllocHGlobal(SystemInfoLength);
                Helpers.ZeroMemory(SystemInfoBuffer, SystemInfoLength);

                ntstatus = Syscall.NtQuerySystemInformation(
                    Win32Const.SYSTEM_INFORMATION_CLASS.SystemModuleInformation,
                    SystemInfoBuffer,
                    SystemInfoLength,
                    ref SystemInfoLength);
                
                if (ntstatus != STATUS_SUCCESS)
                    Marshal.FreeHGlobal(SystemInfoBuffer);
            } while (ntstatus == STATUS_INFO_LENGTH_MISMATCH);

            if (ntstatus != STATUS_SUCCESS)
            {
                Console.WriteLine("[-] Failed to get system information.");
                Console.WriteLine("    |-> {0}\n", Helpers.GetWin32ErrorMessage(ntstatus, true));
            }

            int entryCount = Marshal.ReadInt32(SystemInfoBuffer);
            var entry = new Win32Struct.SYSTEM_MODULE_INFORMATION();
            int sizeEntry = Marshal.SizeOf(entry);
            IntPtr offsetBuffer = new IntPtr(SystemInfoBuffer.ToInt64() + IntPtr.Size);

            Console.WriteLine("[+] Got {0} entries.\n", entryCount);

            if (entryCount > 0)
            {
                Console.WriteLine("DRIVERS INFORMATION");
                Console.WriteLine("-------------------\n");
                Console.WriteLine("Index Base Address       Driver Name");
                Console.WriteLine("===== ================== ==============");
            }

            for (var idx = 0; idx < entryCount; idx++)
            {
                entry = (Win32Struct.SYSTEM_MODULE_INFORMATION)Marshal.PtrToStructure(
                    offsetBuffer,
                    typeof(Win32Struct.SYSTEM_MODULE_INFORMATION));

                Console.WriteLine(
                    "{0,5} 0x{1,-16} {2}",
                    idx,
                    entry.ImageBase.ToString("X"),
                    Encoding.ASCII.GetString(entry.ImageName).Trim('\x00'));
                
                offsetBuffer = new IntPtr(offsetBuffer.ToInt64() + sizeEntry);
            }

            Marshal.FreeHGlobal(SystemInfoBuffer);

            Console.WriteLine("\n[*] Done.\n");
        }
    }
}
