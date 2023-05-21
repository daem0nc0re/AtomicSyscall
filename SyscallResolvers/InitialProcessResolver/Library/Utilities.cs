using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using InitialProcessResolver.Interop;

namespace InitialProcessResolver.Library
{
    using NTSTATUS = Int32;
    using SIZE_T = UIntPtr;

    internal class Utilities
    {
        public static bool CreateInitialProcess(out IntPtr hProcess, out IntPtr hThread)
        {
            NTSTATUS ntstatus;
            var imagePathName = new UNICODE_STRING(@"\??\C:\Windows\System32\svchost.exe");
            var currentDirectory = new UNICODE_STRING(@"C:\Windows\System32");
            var desktopInfo = new UNICODE_STRING(@"WinSta0\Default");
            var commandLine = new UNICODE_STRING(@"C:\Windows\System32\svchost.exe");
            var windowTitle = new UNICODE_STRING(@"svchost.exe");
            var createInfo = new PS_CREATE_INFO
            {
                Size = new SIZE_T((uint)Marshal.SizeOf(typeof(PS_CREATE_INFO))),
                State = PS_CREATE_STATE.PsCreateInitialState
            };
            var attributeList = new PS_ATTRIBUTE_LIST(1);
            attributeList.Attributes[0].Attribute = new UIntPtr((uint)PS_ATTRIBUTES.IMAGE_NAME);
            attributeList.Attributes[0].Size = new SIZE_T((uint)imagePathName.Length);
            attributeList.Attributes[0].Value = imagePathName.GetBuffer();
            hProcess = IntPtr.Zero;
            hThread = IntPtr.Zero;

            ntstatus = NativeMethods.RtlCreateProcessParametersEx(
                out IntPtr pProcessParameters,
                in imagePathName,
                IntPtr.Zero,
                in currentDirectory,
                in commandLine,
                IntPtr.Zero,
                in windowTitle,
                in desktopInfo,
                IntPtr.Zero,
                IntPtr.Zero,
                RTL_USER_PROC_FLAGS.PARAMS_NORMALIZED);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                ntstatus = NativeMethods.NtCreateUserProcess(
                    out hProcess,
                    out hThread,
                    ACCESS_MASK.MAXIMUM_ALLOWED,
                    ACCESS_MASK.MAXIMUM_ALLOWED,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    PROCESS_CREATION_FLAGS.SUSPENDED,
                    THREAD_CREATION_FLAGS.CREATE_SUSPENDED,
                    pProcessParameters,
                    ref createInfo,
                    in attributeList);
                NativeMethods.RtlDestroyProcessParameters(pProcessParameters);
            }

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }


        public static bool GetRemoteNtcalls(
            IntPtr hProcess,
            IntPtr pImageBase,
            out IMAGE_FILE_MACHINE architecture,
            out Dictionary<string, int> exports)
        {
            IntPtr pHeaderBuffer = Marshal.AllocHGlobal(0x1000);
            var pDirectoryBuffer = IntPtr.Zero;
            var status = false;
            architecture = IMAGE_FILE_MACHINE.UNKNOWN;
            exports = new Dictionary<string, int>();

            do
            {
                int e_lfanew;
                int nExportDirectoryOffset;
                int nExportDirectorySize;
                IntPtr pExportDirectory;
                NTSTATUS ntstatus = NativeMethods.NtReadVirtualMemory(
                    hProcess,
                    pImageBase,
                    pHeaderBuffer,
                    0x1000u,
                    out uint _);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    break;

                if (Marshal.ReadInt16(pHeaderBuffer) != 0x5A4D)
                    break;

                e_lfanew = Marshal.ReadInt32(pHeaderBuffer, 0x3C);

                if (e_lfanew > 0x800)
                    break;

                architecture = (IMAGE_FILE_MACHINE)Marshal.ReadInt16(pHeaderBuffer, e_lfanew + 0x4);

                if ((architecture == IMAGE_FILE_MACHINE.AMD64) ||
                    (architecture == IMAGE_FILE_MACHINE.IA64) ||
                    (architecture == IMAGE_FILE_MACHINE.ARM64))
                {
                    nExportDirectoryOffset = Marshal.ReadInt32(pHeaderBuffer, e_lfanew + 0x88);
                    nExportDirectorySize = Marshal.ReadInt32(pHeaderBuffer, e_lfanew + 0x8C);
                }
                else if ((architecture == IMAGE_FILE_MACHINE.I386) || (architecture == IMAGE_FILE_MACHINE.ARM2))
                {
                    nExportDirectoryOffset = Marshal.ReadInt32(pHeaderBuffer, e_lfanew + 0x78);
                    nExportDirectorySize = Marshal.ReadInt32(pHeaderBuffer, e_lfanew + 0x7C);
                }
                else
                {
                    break;
                }

                if ((nExportDirectoryOffset == 0) || (nExportDirectorySize == 0))
                {
                    status = true;
                    break;
                }

                if (Environment.Is64BitProcess)
                    pExportDirectory = new IntPtr(pImageBase.ToInt64() + nExportDirectoryOffset);
                else
                    pExportDirectory = new IntPtr(pImageBase.ToInt32() + nExportDirectoryOffset);

                pDirectoryBuffer = Marshal.AllocHGlobal(nExportDirectorySize);
                ntstatus = NativeMethods.NtReadVirtualMemory(
                    hProcess,
                    pExportDirectory,
                    pDirectoryBuffer,
                    (uint)nExportDirectorySize,
                    out uint _);
                status = (ntstatus == Win32Consts.STATUS_SUCCESS);

                if (status)
                {
                    IntPtr pStringBuffer;
                    int nOrdinal;
                    int nFunctionOffset;
                    int nStringOffset;
                    var nNumberOfNames = Marshal.ReadInt32(pDirectoryBuffer, 0x18);
                    var nAddressOfFunctions = Marshal.ReadInt32(pDirectoryBuffer, 0x1C) - nExportDirectoryOffset;
                    var nAddressOfNames = Marshal.ReadInt32(pDirectoryBuffer, 0x20) - nExportDirectoryOffset;
                    var nAddressOfOrdinals = Marshal.ReadInt32(pDirectoryBuffer, 0x24) - nExportDirectoryOffset;

                    for (var index = 0; index < nNumberOfNames; index++)
                    {
                        nStringOffset = Marshal.ReadInt32(pDirectoryBuffer, nAddressOfNames + (index * 4)) - nExportDirectoryOffset;
                        nOrdinal = Marshal.ReadInt16(pDirectoryBuffer, nAddressOfOrdinals + (index * 2));
                        nFunctionOffset = Marshal.ReadInt32(pDirectoryBuffer, nAddressOfFunctions + (nOrdinal * 4));

                        if (Environment.Is64BitProcess)
                            pStringBuffer = new IntPtr(pDirectoryBuffer.ToInt64() + nStringOffset);
                        else
                            pStringBuffer = new IntPtr(pDirectoryBuffer.ToInt32() + nStringOffset);

                        if (Marshal.PtrToStringAnsi(pStringBuffer).StartsWith(@"Nt"))
                            exports.Add(Marshal.PtrToStringAnsi(pStringBuffer), nFunctionOffset);
                    }
                }
            } while (false);

            if (pDirectoryBuffer != IntPtr.Zero)
                Marshal.FreeHGlobal(pDirectoryBuffer);

            Marshal.FreeHGlobal(pHeaderBuffer);

            return status;
        }
    }
}
