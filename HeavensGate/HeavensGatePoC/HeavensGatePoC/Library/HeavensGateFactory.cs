using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.IO.MemoryMappedFiles;

namespace HeavensGatePoC.Library
{
    internal class HeavensGateFactory
    {
        /*
         * Structs
         */
        public struct FUNCTION_CONTEXT
        {
            public IntPtr FunctionBuffer;
            public IntPtr ContextBuffer;
        }

        /*
         * Shellcodes
         */
        private static readonly List<byte> enter64BitBytes = new List<byte>
        {
            // [32BITS]
            0x53,                         // push   ebx
            0x51,                         // push   ecx
            0x52,                         // push   edx
            0x55,                         // push   ebp
            0x56,                         // push   esi
            0x9C,                         // pushf
            0xEB, 0x05,                   // jmp    d <invoker>
            // enter64:
            0x59,                         // pop    ecx
            0x6A, 0x33,                   // push   0x33
            0x51,                         // push   ecx
            0xCB,                         // retf
            // invoker:
            0xE8, 0xF6, 0xFF, 0xFF, 0xFF, // call   8 <enter64>
            // [64BITS]
            0x48, 0x89, 0xE6,             // mov    rsi,rsp
            0x48, 0x83, 0xE4, 0xF0,       // and    rsp,0xfffffffffffffff0
        };
        private static readonly List<byte> exit64BitBytes = new List<byte>
        {
            // [64BITS]
            0xEB, 0x14,                                     // jmp    16 <invoker>
            // exit64:
            0x59,                                           // pop    rcx
            0x48, 0x89, 0xF4,                               // mov    rsp,rsi
            0x48, 0x83, 0xEC, 0x08,                         // sub    rsp,0x8
            0xC7, 0x44, 0x24, 0x04, 0x23, 0x00, 0x00, 0x00, // mov    DWORD PTR [rsp+0x4],0x23
            0x89, 0x0C, 0x24,                               // mov    DWORD PTR [rsp],ecx
            0xCB,                                           // retf
            // invoker:
            0xE8, 0xE7, 0xFF, 0xFF, 0xFF,                   // call   2 <exit64>
            // [32BITS]
            0x9D,                                           // popf
            0x5E,                                           // pop    esi
            0x5D,                                           // pop    ebp
            0x5A,                                           // pop    edx
            0x59,                                           // pop    ecx
            0x5B,                                           // pop    ebx
            0xC3                                            // ret
        };
        private static readonly List<byte> syscallBytes = new List<byte>
        {
            // [64BITS]
            0xEB, 0x0B,                   // jmp    d <invoker>
            // syscaller:
            0x49, 0x89, 0xCA,             // mov    r10,rcx
            0xB8, 0x44, 0x43, 0x42, 0x41, // mov    eax,0x41424344
            0x0F, 0x05,                   // syscall
            0xC3,                         // ret
            // invoker:
            0xE8, 0xF0, 0xFF, 0xFF, 0xFF  // call   2 <syscaller>
        };

        /*
         * Global Parameters
         */
        private static Dictionary<string, int> g_SyscallNumberTable = new Dictionary<string, int>();
        private static readonly List<MemoryMappedFile> g_MemoryMaps = new List<MemoryMappedFile>();
        private static IntPtr g_CurrentPagePointer = IntPtr.Zero;
        private static int g_CurrentSize = 0;
        public static readonly Dictionary<string, FUNCTION_CONTEXT> g_ExportTable = new Dictionary<string, FUNCTION_CONTEXT>();

        /*
         * Functions
         */
        public static bool AddShellcode(string functionName, byte[] shellcode)
        {
            return AddShellcode(functionName, shellcode, IntPtr.Zero);
        }


        public static bool AddShellcode(string functionName, byte[] shellcode, IntPtr pContext)
        {
            FUNCTION_CONTEXT context;
            var shellcodeBytes = new List<byte>();

            foreach (var code in enter64BitBytes)
                shellcodeBytes.Add(code);

            for (var idx = 0; idx < shellcode.Length; idx++)
                shellcodeBytes.Add(shellcode[idx]);

            foreach (var code in exit64BitBytes)
                shellcodeBytes.Add(code);

            if ((g_CurrentPagePointer == IntPtr.Zero) ||
                ((g_CurrentSize + shellcodeBytes.Count) > 0x1000))
            {
                g_CurrentPagePointer = AllocateRwxPage();
                g_CurrentSize = 0;
            }

            if (g_CurrentPagePointer == IntPtr.Zero)
                return false;

            context = new FUNCTION_CONTEXT
            {
                FunctionBuffer = new IntPtr(g_CurrentPagePointer.ToInt32() + g_CurrentSize),
                ContextBuffer = pContext
            };
            Marshal.Copy(shellcodeBytes.ToArray(), 0, context.FunctionBuffer, shellcodeBytes.Count);
            g_ExportTable.Add(functionName, context);
            g_CurrentSize += ((shellcodeBytes.Count / 0x100) + 1) * 0x100;

            return true;
        }

        public static bool AddSyscall(string syscallName, int numberOfParameters)
        {
            byte[] shellcode;
            int syscallNumber;
            FUNCTION_CONTEXT context;

            if (g_SyscallNumberTable.Count == 0)
                g_SyscallNumberTable = PhysicalResolve.DumpSyscallNumber(@"C:\Windows\System32\ntdll.dll");

            if (!g_SyscallNumberTable.ContainsKey(syscallName))
                return false;

            syscallNumber = g_SyscallNumberTable[syscallName];
            shellcode = GetSyscallBytes(syscallNumber, numberOfParameters, out IntPtr pCoontext);

            if ((g_CurrentPagePointer == IntPtr.Zero) || ((g_CurrentSize + shellcode.Length) > 0x1000))
            {
                g_CurrentPagePointer = AllocateRwxPage();
                g_CurrentSize = 0;
            }

            if (g_CurrentPagePointer == IntPtr.Zero)
                return false;

            context = new FUNCTION_CONTEXT
            {
                FunctionBuffer = new IntPtr(g_CurrentPagePointer.ToInt32() + g_CurrentSize),
                ContextBuffer = pCoontext
            };
            Marshal.Copy(shellcode, 0, context.FunctionBuffer, shellcode.Length);
            g_ExportTable.Add(syscallName, context);
            g_CurrentSize += ((shellcode.Length / 0x100) + 1) * 0x100;

            return true;
        }


        private static IntPtr AllocateRwxPage()
        {
            IntPtr pBuffer;
            MemoryMappedFile memMap;
            MemoryMappedViewAccessor accessor;

            memMap = MemoryMappedFile.CreateNew(
                null,
                0x1000,
                MemoryMappedFileAccess.ReadWriteExecute);
            accessor = memMap.CreateViewAccessor(
                0,
                0x1000,
                MemoryMappedFileAccess.ReadWriteExecute);
            pBuffer = accessor.SafeMemoryMappedViewHandle.DangerousGetHandle();

            if (pBuffer != IntPtr.Zero)
                g_MemoryMaps.Add(memMap);

            return pBuffer;
        }


        private static byte[] GetSyscallBytes(
            int syscallNumber,
            int numberOfParameters,
            out IntPtr pContext)
        {
            byte[] setParameterBytes;
            byte[] addressBytes;
            byte nStackSize;
            byte nStackOffset;
            byte[] syscallNumberBytes = BitConverter.GetBytes(syscallNumber);
            var returnBytes = new List<byte>();

            for (var idx = 0; idx < syscallNumberBytes.Length; idx++)
                syscallBytes[6 + idx] = syscallNumberBytes[idx];

            if (numberOfParameters > 0)
                pContext = Marshal.AllocHGlobal(8 * numberOfParameters);
            else
                pContext = IntPtr.Zero;

            foreach (var code in enter64BitBytes)
                returnBytes.Add(code);

            if (numberOfParameters > 4)
                nStackSize = (byte)(0x20 + (8 * (numberOfParameters - 4)));
            else
                nStackSize = 0;

            for (var idx = 0; idx < numberOfParameters; idx++)
            {
                addressBytes = BitConverter.GetBytes(pContext.ToInt32() + (8 * idx));

                if (idx == 0)
                {
                    setParameterBytes = new byte[]
                    {
                        0x48, 0x8B, 0x0C, 0x25, 0x44, 0x43, 0x42, 0x41, // mov    rcx,QWORD PTR ds:0x41424344
                    };
                    Buffer.BlockCopy(addressBytes, 0, setParameterBytes, 4, 4);

                    for (var offset = 0; offset < setParameterBytes.Length; offset++)
                        returnBytes.Add(setParameterBytes[offset]);
                }
                else if (idx == 1)
                {
                    setParameterBytes = new byte[]
                    {
                        0x48, 0x8B, 0x14, 0x25, 0x44, 0x43, 0x42, 0x41, // mov    rdx,QWORD PTR ds:0x41424344
                    };
                    Buffer.BlockCopy(addressBytes, 0, setParameterBytes, 4, 4);

                    for (var offset = 0; offset < setParameterBytes.Length; offset++)
                        returnBytes.Add(setParameterBytes[offset]);
                }
                else if (idx == 2)
                {
                    setParameterBytes = new byte[]
                    {
                        0x4C, 0x8B, 0x04, 0x25, 0x44, 0x43, 0x42, 0x41, // mov    r8,QWORD PTR ds:0x41424344
                    };
                    Buffer.BlockCopy(addressBytes, 0, setParameterBytes, 4, 4);

                    for (var offset = 0; offset < setParameterBytes.Length; offset++)
                        returnBytes.Add(setParameterBytes[offset]);
                }
                else if (idx == 3)
                {
                    setParameterBytes = new byte[]
                    {
                        0x4C, 0x8B, 0x0C, 0x25, 0x44, 0x43, 0x42, 0x41, // mov    r9,QWORD PTR ds:0x41424344
                    };
                    Buffer.BlockCopy(addressBytes, 0, setParameterBytes, 4, 4);

                    for (var offset = 0; offset < setParameterBytes.Length; offset++)
                        returnBytes.Add(setParameterBytes[offset]);
                }
                else if (idx > 3)
                {
                    nStackOffset = (byte)(0x20 + (8 * (idx - 4)));

                    if (idx == 4)
                    {
                        setParameterBytes = new byte[]
                        {
                            0x48, 0x83, 0xEC, nStackSize // sub    rsp,nStackSize
                        };

                        for (var offset = 0; offset < setParameterBytes.Length; offset++)
                            returnBytes.Add(setParameterBytes[offset]);
                    }

                    setParameterBytes = new byte[]
                    {
                        0x48, 0x8B, 0x04, 0x25, 0x44, 0x43, 0x42, 0x41, // mov    rax,QWORD PTR ds:0x41424344
                        0x48, 0x89, 0x44, 0x24, nStackOffset            // mov    QWORD PTR [rsp+nStackOffset],rax
                    };
                    Buffer.BlockCopy(addressBytes, 0, setParameterBytes, 4, 4);

                    for (var offset = 0; offset < setParameterBytes.Length; offset++)
                        returnBytes.Add(setParameterBytes[offset]);
                }
            }

            foreach (var code in syscallBytes)
                returnBytes.Add(code);

            foreach (var code in exit64BitBytes)
                returnBytes.Add(code);

            return returnBytes.ToArray();
        }
    }
}
