using System;
using System.Runtime.InteropServices;

namespace KnownDllsResolver.Interop
{
    using NTSTATUS = Int32;
    using SIZE_T = UIntPtr;

    internal class NativeMethods
    {
        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtClose(IntPtr Handle);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtMapViewOfSection(
            IntPtr SectionHandle,
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            UIntPtr ZeroBits,
            SIZE_T CommitSize,
            IntPtr /* PLARGE_INTEGER */ SectionOffset,
            ref SIZE_T ViewSize,
            SECTION_INHERIT InheritDisposition,
            ALLOCATION_TYPE AllocationType, // Must be MEM_LARGE_PAGES, MEM_RESERVE, MEM_TOP_DOWN or NONE. 
            MEMORY_PROTECTION Win32Protect);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtOpenSection(
            ref IntPtr SectionHandle,
            ACCESS_MASK DesiredAccess,
            ref OBJECT_ATTRIBUTES ObjectAttributes);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtUnmapViewOfSection(
            IntPtr ProcessHandle,
            IntPtr BaseAddress);
    }
}
