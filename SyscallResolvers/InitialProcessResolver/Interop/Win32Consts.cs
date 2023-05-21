using System;

namespace InitialProcessResolver.Interop
{
    using NTSTATUS = Int32;

    internal class Win32Consts
    {
        public const NTSTATUS STATUS_SUCCESS = 0;
        public static IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
    }
}
