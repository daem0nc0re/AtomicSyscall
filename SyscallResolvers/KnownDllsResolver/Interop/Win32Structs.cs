﻿using System;
using System.Runtime.InteropServices;
using System.Text;

namespace KnownDllsResolver.Interop
{
    using SIZE_T = UIntPtr;

    [StructLayout(LayoutKind.Explicit, Size = 8)]
    internal struct LARGE_INTEGER
    {
        [FieldOffset(0)]
        public int Low;
        [FieldOffset(4)]
        public int High;
        [FieldOffset(0)]
        public long QuadPart;

        public LARGE_INTEGER(int _low, int _high)
        {
            QuadPart = 0L;
            Low = _low;
            High = _high;
        }

        public LARGE_INTEGER(long _quad)
        {
            Low = 0;
            High = 0;
            QuadPart = _quad;
        }

        public long ToInt64()
        {
            return ((long)High << 32) | (uint)Low;
        }

        public static LARGE_INTEGER FromInt64(long value)
        {
            return new LARGE_INTEGER
            {
                Low = (int)(value),
                High = (int)((value >> 32))
            };
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct OBJECT_ATTRIBUTES : IDisposable
    {
        public int Length;
        public IntPtr RootDirectory;
        private IntPtr objectName;
        public OBJECT_ATTRIBUTES_FLAGS Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;

        public OBJECT_ATTRIBUTES(
            string name,
            OBJECT_ATTRIBUTES_FLAGS attrs)
        {
            Length = 0;
            RootDirectory = IntPtr.Zero;
            objectName = IntPtr.Zero;
            Attributes = attrs;
            SecurityDescriptor = IntPtr.Zero;
            SecurityQualityOfService = IntPtr.Zero;

            Length = Marshal.SizeOf(this);
            ObjectName = new UNICODE_STRING(name);
        }

        public UNICODE_STRING ObjectName
        {
            get
            {
                return (UNICODE_STRING)Marshal.PtrToStructure(
                 objectName, typeof(UNICODE_STRING));
            }

            set
            {
                bool fDeleteOld = objectName != IntPtr.Zero;
                if (!fDeleteOld)
                    objectName = Marshal.AllocHGlobal(Marshal.SizeOf(value));
                Marshal.StructureToPtr(value, objectName, fDeleteOld);
            }
        }

        public void Dispose()
        {
            if (objectName != IntPtr.Zero)
            {
                Marshal.DestroyStructure(objectName, typeof(UNICODE_STRING));
                Marshal.FreeHGlobal(objectName);
                objectName = IntPtr.Zero;
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SECTION_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public ulong AllocationAttributes;
        LARGE_INTEGER MaximumSize;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SECTION_IMAGE_INFORMATION
    {
        public IntPtr TransferAddress;
        public uint ZeroBits;
        public SIZE_T MaximumStackSize;
        public SIZE_T CommittedStackSize;
        public uint SubSystemType;
        public uint SubSystemVersion;
        public uint OperatingSystemVersion;
        public ushort ImageCharacteristics;
        public ushort DllCharacteristics;
        public ushort Machine;
        public byte ImageContainsCode;
        public byte ImageFlags;
        public uint LoaderFlags;
        public uint ImageFileSize;
        public uint CheckSum;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct UNICODE_STRING : IDisposable
    {
        public ushort Length;
        public ushort MaximumLength;
        private IntPtr buffer;

        public UNICODE_STRING(string s)
        {
            byte[] bytes;

            if (string.IsNullOrEmpty(s))
            {
                Length = 0;
                bytes = new byte[2];
            }
            else
            {
                Length = (ushort)(s.Length * 2);
                bytes = Encoding.Unicode.GetBytes(s);
            }

            MaximumLength = (ushort)(Length + 2);
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
            return Marshal.PtrToStringUni(buffer, Length / 2);
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
}
