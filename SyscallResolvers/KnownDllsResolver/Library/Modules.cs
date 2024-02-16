using System;
using System.Collections.Generic;
using KnownDllsResolver.Interop;

namespace KnownDllsResolver.Library
{
    using NTSTATUS = Int32;
    using SIZE_T = UIntPtr;

    internal class Modules
    {
        public static int ResolveSyscallNumber(string syscallName)
        {
            NTSTATUS ntstatus;
            int nSyscallNumber = -1;
            var hSection = IntPtr.Zero;
            var objectPath = @"\KnownDlls\ntdll.dll";

            if (Environment.Is64BitOperatingSystem && !Environment.Is64BitProcess)
            {
                Console.WriteLine("[!] Should be built as 64bit binary.");
                return -1;
            }

            if (string.IsNullOrEmpty(syscallName))
            {
                Console.WriteLine("[!] Syscall name string must be specified.");
                return -1;
            }

            Console.WriteLine("[>] Trying to get section handle to {0}.", objectPath);

            using (var objectAttributes = new OBJECT_ATTRIBUTES(
                objectPath,
                OBJECT_ATTRIBUTES_FLAGS.OBJ_CASE_INSENSITIVE))
            {
                ntstatus = NativeMethods.NtOpenSection(
                    out hSection,
                    ACCESS_MASK.SECTION_MAP_READ,
                    in objectAttributes);
            }

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                Console.WriteLine("[-] Failed to NtOpenSection() (NTSTATUS = 0x{0}).", ntstatus.ToString("X8"));
                return -1;
            }

            do
            {
                Dictionary<string, int> syscallTable;
                var pMappedSection = IntPtr.Zero;
                var nViewSize = SIZE_T.Zero;

                Console.WriteLine("[+] Got a section handle from {0} (Handle = 0x{1}).", objectPath, hSection.ToString("X"));

                ntstatus = NativeMethods.NtMapViewOfSection(
                    hSection,
                    new IntPtr(-1),
                    ref pMappedSection,
                    UIntPtr.Zero,
                    SIZE_T.Zero,
                    IntPtr.Zero,
                    ref nViewSize,
                    SECTION_INHERIT.ViewUnmap,
                    ALLOCATION_TYPE.NONE,
                    MEMORY_PROTECTION.PAGE_NOACCESS);

                if ((ntstatus != Win32Consts.STATUS_SUCCESS) && (ntstatus != Win32Consts.STATUS_IMAGE_NOT_AT_BASE))
                {
                    Console.WriteLine("[-] Failed to NtMapViewOfSection() (NTSTATUS = 0x{0}).", ntstatus.ToString("X8"));
                    break;
                }
                else
                {
                    Console.WriteLine("[+] {0} is mapped at 0x{1}.", objectPath, pMappedSection.ToString("X16"));
                }

                syscallTable = Utilities.GetSyscallTableFromMappedSection(pMappedSection);

                foreach (var entry in syscallTable)
                {
                    if (entry.Key.IndexOf(syscallName, StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        syscallName = entry.Key;
                        nSyscallNumber = entry.Value;
                        break;
                    }
                }

                if (nSyscallNumber == -1)
                {
                    Console.WriteLine("[-] \"{0}\" is not found.", syscallName);
                }
                else
                {
                    Console.WriteLine("[+] Syscall number is resolved successfully.");
                    Console.WriteLine("    [*] Syscall Name   : {0}", syscallName);
                    Console.WriteLine("    [*] Syscall Number : {0} (0x{1})", nSyscallNumber, nSyscallNumber.ToString("X"));
                }

                NativeMethods.NtUnmapViewOfSection(new IntPtr(-1), pMappedSection);
            } while (false);

            NativeMethods.NtClose(hSection);

            Console.WriteLine("[*] Done.");

            return nSyscallNumber;
        }
    }
}
