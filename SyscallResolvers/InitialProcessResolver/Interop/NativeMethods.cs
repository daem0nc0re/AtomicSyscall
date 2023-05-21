using System;
using System.Runtime.InteropServices;

namespace InitialProcessResolver.Interop
{
    using NTSTATUS = Int32;

    internal class NativeMethods
    {
        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtClose(IntPtr Handle);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtCreateUserProcess(
            out IntPtr ProcessHandle,
            out IntPtr ThreadHandle,
            ACCESS_MASK ProcessDesiredAccess,
            ACCESS_MASK ThreadDesiredAccess,
            in OBJECT_ATTRIBUTES ProcessObjectAttributes,
            in OBJECT_ATTRIBUTES ThreadObjectAttributes,
            PROCESS_CREATION_FLAGS ProcessFlags,
            THREAD_CREATION_FLAGS ThreadFlags,
            in RTL_USER_PROCESS_PARAMETERS ProcessParameters,
            ref PS_CREATE_INFO CreateInfo,
            in PS_ATTRIBUTE_LIST AttributeList);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtCreateUserProcess(
            out IntPtr ProcessHandle,
            out IntPtr ThreadHandle,
            ACCESS_MASK ProcessDesiredAccess,
            ACCESS_MASK ThreadDesiredAccess,
            IntPtr ProcessObjectAttributes,
            IntPtr ThreadObjectAttributes,
            PROCESS_CREATION_FLAGS ProcessFlags,
            THREAD_CREATION_FLAGS ThreadFlags,
            IntPtr ProcessParameters,
            ref PS_CREATE_INFO CreateInfo,
            IntPtr AttributeList);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtCreateUserProcess(
            out IntPtr ProcessHandle,
            out IntPtr ThreadHandle,
            ACCESS_MASK ProcessDesiredAccess,
            ACCESS_MASK ThreadDesiredAccess,
            IntPtr ProcessObjectAttributes,
            IntPtr ThreadObjectAttributes,
            PROCESS_CREATION_FLAGS ProcessFlags,
            THREAD_CREATION_FLAGS ThreadFlags,
            IntPtr ProcessParameters,
            ref PS_CREATE_INFO CreateInfo,
            in PS_ATTRIBUTE_LIST AttributeList);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtQueryInformationProcess(
            IntPtr ProcessHandle,
            PROCESSINFOCLASS ProcessInformationClass,
            IntPtr pProcessInformation,
            uint ProcessInformationLength,
            out uint ReturnLength);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtReadVirtualMemory(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            IntPtr Buffer,
            uint NumberOfBytesToRead,
            out uint NumberOfBytesReaded);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtTerminateProcess(
            IntPtr ProcessHandle,
            NTSTATUS ExitStatus);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS RtlCreateProcessParametersEx(
            out IntPtr /* PRTL_USER_PROCESS_PARAMETERS */ pProcessParameters,
            in UNICODE_STRING ImagePathName,
            in UNICODE_STRING DllPath,
            in UNICODE_STRING CurrentDirectory,
            in UNICODE_STRING CommandLine,
            IntPtr Environment,
            in UNICODE_STRING WindowTitle,
            in UNICODE_STRING DesktopInfo,
            IntPtr pShellInfo,
            IntPtr pRuntimeData,
            RTL_USER_PROC_FLAGS Flags); // pass RTL_USER_PROC_PARAMS_NORMALIZED to keep parameters normalized

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS RtlCreateProcessParametersEx(
            out IntPtr /* PRTL_USER_PROCESS_PARAMETERS */ pProcessParameters,
            in UNICODE_STRING ImagePathName,
            IntPtr DllPath,
            in UNICODE_STRING CurrentDirectory,
            in UNICODE_STRING CommandLine,
            IntPtr Environment,
            in UNICODE_STRING WindowTitle,
            in UNICODE_STRING DesktopInfo,
            IntPtr pShellInfo,
            IntPtr pRuntimeData,
            RTL_USER_PROC_FLAGS Flags); // pass RTL_USER_PROC_PARAMS_NORMALIZED to keep parameters normalized

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS RtlDestroyProcessParameters(
            IntPtr /* PRTL_USER_PROCESS_PARAMETERS */ pProcessParameters);
    }
}
