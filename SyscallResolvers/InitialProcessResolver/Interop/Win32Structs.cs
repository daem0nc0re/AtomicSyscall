using System;
using System.Runtime.InteropServices;
using System.Text;

namespace InitialProcessResolver.Interop
{
    using NTSTATUS = Int32;
    using SIZE_T = UIntPtr;

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_BASIC_INFORMATION
    {
        public NTSTATUS ExitStatus;
        public IntPtr PebBaseAddress;
        public UIntPtr AffinityMask;
        public int BasePriority;
        public UIntPtr UniqueProcessId;
        public UIntPtr InheritedFromUniqueProcessId;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PS_ATTRIBUTE
    {
        public UIntPtr Attribute; // PS_ATTRIBUTES
        public SIZE_T Size;
        public IntPtr Value;
        public IntPtr /* PSIZE_T */ ReturnLength;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PS_ATTRIBUTE_LIST
    {
        public SIZE_T TotalLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public PS_ATTRIBUTE[] Attributes;

        public PS_ATTRIBUTE_LIST(int nAttributes)
        {
            int length;

            if (nAttributes < 8)
                length = 8;
            else
                length = nAttributes;

            Attributes = new PS_ATTRIBUTE[length];
            TotalLength = new SIZE_T((uint)(
                Marshal.SizeOf(typeof(SIZE_T)) +
                (Marshal.SizeOf(typeof(PS_ATTRIBUTE)) * nAttributes)));
        }

        public PS_ATTRIBUTE_LIST(PS_ATTRIBUTE[] attributes)
        {
            int length;

            if (attributes.Length < 8)
                length = 8;
            else
                length = attributes.Length;

            Attributes = new PS_ATTRIBUTE[length];

            for (var idx = 0; idx < attributes.Length; idx++)
            {
                Attributes[idx].Attribute = attributes[idx].Attribute;
                Attributes[idx].Size = attributes[idx].Size;
                Attributes[idx].Value = attributes[idx].Value;
            }

            TotalLength = new SIZE_T((uint)(
                Marshal.SizeOf(typeof(SIZE_T)) +
                (Marshal.SizeOf(typeof(PS_ATTRIBUTE)) * length)));
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PS_CREATE_EXE_FORMAT
    {
        public ushort DllCharacteristics;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PS_CREATE_EXE_NAME
    {
        public IntPtr IFEOKey;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PS_CREATE_FAIL_SECTION
    {
        public IntPtr FileHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PS_CREATE_INFO
    {
        public SIZE_T Size;
        public PS_CREATE_STATE State;
        public PS_CREATE_INFO_UNION Information;
    }

    [StructLayout(LayoutKind.Explicit)]
    internal struct PS_CREATE_INFO_UNION
    {
        [FieldOffset(0)]
        public PS_CREATE_INITIAL_STATE InitState; // PsCreateInitialState

        [FieldOffset(0)]
        public PS_CREATE_FAIL_SECTION FailSection; // PsCreateFailOnSectionCreate

        [FieldOffset(0)]
        public PS_CREATE_EXE_FORMAT ExeFormat; // PsCreateFailExeFormat

        [FieldOffset(0)]
        public PS_CREATE_EXE_NAME ExeName; // PsCreateFailExeName

        [FieldOffset(0)]
        public PS_CREATE_SUCCESS_STATE SuccessState; // PsCreateSuccess
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PS_CREATE_INITIAL_STATE
    {
        public PS_CREATE_INIT_FLAGS InitFlags;
        public ACCESS_MASK AdditionalFileAccess;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PS_CREATE_SUCCESS_STATE
    {
        public PS_CREATE_OUTPUT_FLAGS OutputFlags;
        public IntPtr FileHandle;
        public IntPtr SectionHandle;
        public ulong UserProcessParametersNative;
        public uint UserProcessParametersWow64;
        public uint CurrentParameterFlags;
        public ulong PebAddressNative;
        public uint PebAddressWow64;
        public ulong ManifestAddress;
        public uint ManifestSize;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct RTL_DRIVE_LETTER_CURDIR
    {
        public ushort Flags;
        public ushort Length;
        public uint TimeStamp;
        public STRING DosPath;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct STRING : IDisposable
    {
        public ushort Length;
        public ushort MaximumLength;
        private IntPtr buffer;

        public STRING(string s)
        {
            byte[] bytes;

            if (string.IsNullOrEmpty(s))
            {
                Length = 0;
                bytes = new byte[1];
            }
            else
            {
                Length = (ushort)s.Length;
                bytes = Encoding.ASCII.GetBytes(s);
            }

            MaximumLength = (ushort)(Length + 1);
            buffer = Marshal.AllocHGlobal(MaximumLength);

            Marshal.Copy(new byte[MaximumLength], 0, buffer, MaximumLength);
            Marshal.Copy(bytes, 0, buffer, bytes.Length);
        }

        public void Dispose()
        {
            Marshal.FreeHGlobal(buffer);
            buffer = IntPtr.Zero;
        }

        public override string ToString()
        {
            return Marshal.PtrToStringAnsi(buffer);
        }

        public IntPtr GetBuffer()
        {
            return buffer;
        }

        public void SetBuffer(IntPtr _buffer)
        {
            buffer = _buffer;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct UNICODE_STRING : IDisposable
    {
        public ushort Length;
        public ushort MaximumLength;
        private IntPtr buffer;

        public UNICODE_STRING(string s)
        {
            Length = (ushort)(s.Length * 2);
            MaximumLength = (ushort)(Length + 2);
            buffer = Marshal.StringToHGlobalUni(s);
        }

        public void Dispose()
        {
            Marshal.FreeHGlobal(buffer);
            buffer = IntPtr.Zero;
        }

        public IntPtr GetBuffer()
        {
            return buffer;
        }

        public void SetBuffer(IntPtr _buffer)
        {
            buffer = _buffer;
        }

        public override string ToString()
        {
            if ((Length == 0) || (buffer == IntPtr.Zero))
                return null;
            else
                return Marshal.PtrToStringUni(buffer, Length / 2);
        }
    }
}
