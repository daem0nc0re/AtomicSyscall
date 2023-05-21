# AtomicSyscall
Tools and PoCs for Windows syscall investigation.


## Table Of Contents

- [AtomicSyscall](#atomicsyscall)
  - [HeavensGate](#heavensgate)
  - [SyscallDumper](#syscalldumper)
  - [SyscallPoCs](#syscallpocs)
  - [SyscallResolvers](#syscallresolvers)
  - [Get-SyscallNumber.ps1](#get-syscallnumberps1)
  - [Reference](#reference)
  - [Acknowledgments](#acknowledgments)

## HeavensGate

This directory is for Heaven's Gate technique.
See [README.md](./HeavensGate/README.md)


## SyscallDumper

[Back to Top](#atomicsyscall)

[Project](./SyscallDumper)

This tool is to dump Windows syscall from `ntdll.dll` or `win32u.dll`:

```
C:\Tools>SyscallDumper.exe -h

SyscallDumper - Tool to dump syscall.

Usage: SyscallDumper.exe [Options] [INPUT_DLL_1] [INPUT_DLL_2]

        -h, --help   : Displays this help message.
        -d, --dump   : Flag to dump syscall from ntdll.dll or win32u.dll.
        -D, --diff   : Flag to take diff between 2 dlls.
        -f, --format : Specifies output format. "c" for C/C++, "cs" for CSharp, "py" for Python.
        -n, --number : Specifies syscall number to lookup in decimal or hex format.
        -o, --output : Specifies output file (e.g. "-o result.txt").
        -s, --search : Specifies search filter (e.g. "-s createfile").
        INPUT_DLL_1  : Specifies path of ntdll.dll or win32u.dll. Older one in diffing.
        INPUT_DLL_2  : Specifies path of ntdll.dll or win32u.dll. Newer one in diffing.
```

To dump syscall numbers from ntdll.dll or win32u.dll, use `-d` (`--dump`) option.
If you don't specifies source DLL, this tool dumps syscall numbers from `C:\Windows\System32\ntdll.dll` and `C:\Windows\System32\win32u.dll`:

```
C:\Tools>SyscallDumper.exe -d

[*] No target is specified.
[>] Dumping from system default ntdll.dll and win32u.dll.
[>] Loading C:\Windows\System32\ntdll.dll.
[+] C:\Windows\System32\ntdll.dll is loaded successfully.
    [*] Architecture : AMD64
    [*] Image Name   : ntdll.dll
[+] Got 463 syscall(s).
[>] Loading C:\Windows\System32\win32u.dll.
[+] C:\Windows\System32\win32u.dll is loaded successfully.
    [*] Architecture : AMD64
    [*] Image Name   : win32u.dll
[+] Got 1258 syscall(s).

[Syscall Table from C:\Windows\System32\ntdll.dll]

---------------------------------------------------------------------------------
| Syscall Name                                          | Number | Number (hex) |
---------------------------------------------------------------------------------
| NtAcceptConnectPort                                   | 2      | 0x0002       |
| NtAccessCheck                                         | 0      | 0x0000       |

--snip--

| NtWriteVirtualMemory                                  | 58     | 0x003A       |
| NtYieldExecution                                      | 70     | 0x0046       |
---------------------------------------------------------------------------------

[*] Found 463 syscall(s).


[Syscall Table from C:\Windows\System32\win32u.dll]

-----------------------------------------------------------------------------------
| Syscall Name                                            | Number | Number (hex) |
-----------------------------------------------------------------------------------
| NtBindCompositionSurface                                | 4373   | 0x1115       |
| NtCloseCompositionInputSink                             | 4374   | 0x1116       |

--snip--

| NtValidateCompositionSurfaceHandle                      | 5350   | 0x14E6       |
| NtVisualCaptureBits                                     | 5351   | 0x14E7       |
-----------------------------------------------------------------------------------

[*] Found 1258 syscall(s).
```

If you want to filter syscall name from dump result, use `-s` (`--search`) option.
And you can save result to a file with `-o` (`--output`) option as follows:

```
C:\Tools>SyscallDumper.exe -d C:\SyscallSamples\1809x64\ntdll.dll -s token -o result.txt

[>] Loading C:\SyscallSamples\1809x64\ntdll.dll.
[+] C:\SyscallSamples\1809x64\ntdll.dll is loaded successfully.
    [*] Architecture : AMD64
    [*] Image Name   : ntdll.dll
[+] Got 462 syscall(s).
[>] Trying to save results.
    [*] Output File Path : c:\Tools\result.txt
[+] Results are saved successfully.

c:\Tools>type result.txt
[Syscall Table from C:\SyscallSamples\1809x64\ntdll.dll]

--------------------------------------------------------------
| Syscall Name                       | Number | Number (hex) |
--------------------------------------------------------------
| NtAdjustGroupsToken                | 107    | 0x006B       |
| NtAdjustPrivilegesToken            | 65     | 0x0041       |
| NtAdjustTokenClaimsAndDeviceGroups | 108    | 0x006C       |
| NtCompareTokens                    | 155    | 0x009B       |
| NtCreateLowBoxToken                | 172    | 0x00AC       |
| NtCreateToken                      | 191    | 0x00BF       |
| NtCreateTokenEx                    | 192    | 0x00C0       |
| NtDuplicateToken                   | 66     | 0x0042       |
| NtFilterToken                      | 222    | 0x00DE       |
| NtFilterTokenEx                    | 223    | 0x00DF       |
| NtImpersonateAnonymousToken        | 246    | 0x00F6       |
| NtOpenProcessToken                 | 290    | 0x0122       |
| NtOpenProcessTokenEx               | 48     | 0x0030       |
| NtOpenThreadToken                  | 36     | 0x0024       |
| NtOpenThreadTokenEx                | 47     | 0x002F       |
| NtQueryInformationToken            | 33     | 0x0021       |
| NtQuerySecurityAttributesToken     | 339    | 0x0153       |
| NtSetInformationToken              | 404    | 0x0194       |
--------------------------------------------------------------

[*] Found 18 syscall(s).
[*] Filter String : "token"
```

Using `-n` (`--number`) option, you can lookup syscall name by syscall number as follows.
If you want to specifies the syscall number in hex format, should be start with "0x".

```
C:\Tools>SyscallDumper.exe -d C:\dev\SyscallSamples\21H1x64\ntdll.dll -n 85

[>] Loading C:\dev\SyscallSamples\21H1x64\ntdll.dll.
[+] C:\dev\SyscallSamples\21H1x64\ntdll.dll is loaded successfully.
    [*] Architecture : AMD64
    [*] Image Name   : ntdll.dll
[+] Got 470 syscall(s).

[Syscall Table from C:\dev\SyscallSamples\21H1x64\ntdll.dll]

----------------------------------------
| Syscall Name | Number | Number (hex) |
----------------------------------------
| NtCreateFile | 85     | 0x0055       |
----------------------------------------

[*] Found 1 syscall(s).


C:\Tools>SyscallDumper.exe -d C:\dev\SyscallSamples\21H1x64\ntdll.dll -n 0x55

[>] Loading C:\dev\SyscallSamples\21H1x64\ntdll.dll.
[+] C:\dev\SyscallSamples\21H1x64\ntdll.dll is loaded successfully.
    [*] Architecture : AMD64
    [*] Image Name   : ntdll.dll
[+] Got 470 syscall(s).

[Syscall Table from C:\dev\SyscallSamples\21H1x64\ntdll.dll]

----------------------------------------
| Syscall Name | Number | Number (hex) |
----------------------------------------
| NtCreateFile | 85     | 0x0055       |
----------------------------------------

[*] Found 1 syscall(s).
```

If you want to change output format, use `-f` (`--format`) option.
Currently, C/C++ (`c`), CSharp (`cs`) and Python (`py`) are supported:

```
C:\Tools>SyscallDumper.exe -d C:\dev\SyscallSamples\Win11Arm64\ntdll-arm64.dll -f c

[>] Loading C:\dev\SyscallSamples\Win11Arm64\ntdll-arm64.dll.
[+] C:\dev\SyscallSamples\Win11Arm64\ntdll-arm64.dll is loaded successfully.
    [*] Architecture : ARM64
    [*] Image Name   : ntdll.dll
[+] Got 486 syscall(s).

[Syscall Table from C:\dev\SyscallSamples\Win11Arm64\ntdll-arm64.dll]

enum NT_SYSCALLS
{
    NtAcceptConnectPort = 2,
    NtAccessCheck = 0,
    NtAccessCheckAndAuditAlarm = 41,

--snip--

    NtWriteVirtualMemory = 58,
    NtYieldExecution = 70
}

[*] Found 486 syscall(s).



C:\Tools>SyscallDumper.exe -d C:\dev\SyscallSamples\Win11Arm64\ntdll-arm64.dll -f cs

[>] Loading C:\dev\SyscallSamples\Win11Arm64\ntdll-arm64.dll.
[+] C:\dev\SyscallSamples\Win11Arm64\ntdll-arm64.dll is loaded successfully.
    [*] Architecture : ARM64
    [*] Image Name   : ntdll.dll
[+] Got 486 syscall(s).

[Syscall Table from C:\dev\SyscallSamples\Win11Arm64\ntdll-arm64.dll]

public enum NT_SYSCALLS
{
    NtAcceptConnectPort = 2,
    NtAccessCheck = 0,
    NtAccessCheckAndAuditAlarm = 41,


--snip--

    NtWriteVirtualMemory = 58,
    NtYieldExecution = 70
}

[*] Found 486 syscall(s).



C:\Tools>SyscallDumper.exe -d C:\dev\SyscallSamples\Win11Arm64\ntdll-arm64.dll -f py

[>] Loading C:\dev\SyscallSamples\Win11Arm64\ntdll-arm64.dll.
[+] C:\dev\SyscallSamples\Win11Arm64\ntdll-arm64.dll is loaded successfully.
    [*] Architecture : ARM64
    [*] Image Name   : ntdll.dll
[+] Got 486 syscall(s).

[Syscall Table from C:\dev\SyscallSamples\Win11Arm64\ntdll-arm64.dll]

g_NtSyscalls = {
    "NtAcceptConnectPort": 2,
    "NtAccessCheck": 0,
    "NtAccessCheckAndAuditAlarm": 41,
    "NtAccessCheckByType": 99,
    "NtAccessCheckByTypeAndAuditAlarm": 89,

--snip--
```

To take difference between 2 DLL's syscall tables, use `-D` (`--diff`) option as follows:

```
C:\Tools>SyscallDumper.exe -D C:\dev\SyscallSamples\1809x64\win32u.dll C:\dev\SyscallSamples\1903x64\win32u.dll

[>] Trying to take diff.
    [*] Old File : C:\dev\SyscallSamples\1809x64\win32u.dll
    [*] New File : C:\dev\SyscallSamples\1903x64\win32u.dll
[>] Loading C:\dev\SyscallSamples\1809x64\win32u.dll.
[+] C:\dev\SyscallSamples\1809x64\win32u.dll is loaded successfully.
    [*] Architecture : AMD64
    [*] Image Name   : win32u.dll
[+] Got 1242 syscall(s).
[>] Loading C:\dev\SyscallSamples\1903x64\win32u.dll.
[+] C:\dev\SyscallSamples\1903x64\win32u.dll is loaded successfully.
    [*] Architecture : AMD64
    [*] Image Name   : win32u.dll
[+] Got 1258 syscall(s).

################################################
#               DELETED SYSCALLS               #
################################################

-------------------------------------------------------------------
| Syscall Name                            | Number | Number (hex) |
-------------------------------------------------------------------
| NtDCompositionCreateSharedVisualHandle  | 4391   | 0x1127       |
| NtGdiDdDDINetDispStopSessions           | 4608   | 0x1200       |
| NtGdiDdDDISetDisplayPrivateDriverFormat | 4664   | 0x1238       |
| NtMITCoreMsgKGetConnectionHandle        | 4907   | 0x132B       |
| NtMITCoreMsgKSend                       | 4909   | 0x132D       |
| NtMITSynthesizeMouseWheel               | 4919   | 0x1337       |
| NtMITWaitForMultipleObjectsEx           | 4922   | 0x133A       |
| NtUserGetPointerFrameArrivalTimes       | 5105   | 0x13F1       |
-------------------------------------------------------------------

[*] Deleted 8 syscall(s).


################################################
#               MODIFIED SYSCALLS              #
################################################

----------------------------------------------------------------------------------------
| Syscall Name                                       | Number       | Number (hex)     |
----------------------------------------------------------------------------------------
| NtDxgkEndTrackedWorkload                           | 4435 -> 4436 | 0x1153 -> 0x1154 |
| NtDxgkGetAvailableTrackedWorkloadIndex             | 4436 -> 4437 | 0x1154 -> 0x1155 |

--snip--

| NtValidateCompositionSurfaceHandle                 | 5334 -> 5350 | 0x14D6 -> 0x14E6 |
| NtVisualCaptureBits                                | 5335 -> 5351 | 0x14D7 -> 0x14E7 |
----------------------------------------------------------------------------------------

[*] Modified 623 syscall(s).


################################################
#                 NEW SYSCALLS                 #
################################################

-----------------------------------------------------------------------------------
| Syscall Name                                            | Number | Number (hex) |
-----------------------------------------------------------------------------------
| NtDCompositionCreateSharedResourceHandle                | 4391   | 0x1127       |
| NtDxgkDispMgrOperation                                  | 4435   | 0x1153       |

--snip--

| NtUserSetMagnificationDesktopMagnifierOffsetsDWMUpdated | 5283   | 0x14A3       |
| NtUserSetProcessMousewheelRoutingMode                   | 5293   | 0x14AD       |
-----------------------------------------------------------------------------------

[*] Added 24 syscall(s).
```


## SyscallPoCs

[Back to Top](#atomicsyscall)

[Project](./SyscallPoCs)

The purpose of this project is to investigate how attackers resolve and execute Windows syscall.
All PoCs try to list kernel modules by `NtQuerySystemInformation` syscall.

| PoC Name | Description |
| :--- | :--- |
| [PhysicalResolvePoC](./SyscallPoCs/PhysicalResolvePoC) | This PoC simply resolves the syscall numbers of `NtQuerySystemInformation` from `C:\Windows\System32\ntdll.dll`. |
| [HellsGatePoC](./SyscallPoCs/HellsGatePoC) | This PoC resolves the syscall numbers of `NtQuerySystemInformation` by the Hell's Gate technique. |
| [HalosGatePoC](./SyscallPoCs/HalosGatePoC) | This PoC resolves the syscall numbers of `NtQuerySystemInformation` by the Halo's Gate technique. |


## SyscallResolvers

[Back to Top](#atomicsyscall)

[Project](./SyscallResolvers)

The purpose of this project is to help to learn how in-memory syscall number resolve techniques work:

| PoC Name | Description |
| :--- | :--- |
| [HellsGateResolver](./SyscallResolvers/HellsGateResolver) | This PoC resolves the syscall numbers in ntdll.dll by the Hell's Gate technique. Not works for functions patched with anti-virus products. |
| [HalosGateResolver](./SyscallResolvers/HalosGateResolver) | This PoC resolves the syscall numbers in ntdll.dll by the Halo's Gate technique. |
| [InitialProcessResolver](./SyscallResolvers/InitialProcessResolver) | This PoC resolves syscall numbers in ntdll.dll from initial process which created by `NtCreateUserProcess`. |

The following figure shows the difference between Hell's Gate and Halo's Gate in anti-virus software installed environment.
Hell's Gate technique does not work for patched `NtCreateProcessEx` function.
On the other hand, Halo's Gate technique works for patched `NtCreateProcessEx` function:

![syscallresolvers.png](./figures/syscallresolvers.png)

In some anti-virus software installed machine, some ntdll.dll code is hooked as following debugger output:

```
0:001> u ntdll!ntcreateprocessex
ntdll!NtCreateProcessEx:
00007fff`b33ef700 e9930a1800      jmp     00007fff`b3570198
00007fff`b33ef705 cc              int     3
00007fff`b33ef706 cc              int     3
00007fff`b33ef707 cc              int     3
00007fff`b33ef708 f604250803fe7f01 test    byte ptr [SharedUserData+0x308 (00000000`7ffe0308)],1
00007fff`b33ef710 7503            jne     ntdll!NtCreateProcessEx+0x15 (00007fff`b33ef715)
00007fff`b33ef712 0f05            syscall
00007fff`b33ef714 c3              ret
```

But process which created by `NtCreateUserProcess` or `NtCreateProcessEx` are loaded only non-hooked ntdll.dll in initial state.
We can confirm it with scanning suspended initial process memory.
Suspended process cannot be attached with debugger, so I wrote a small tool [ProcMemScan](https://github.com/daem0nc0re/TangledWinExec/tree/main/ProcMemScan).
To test it, I implemented `-d` flag which can pause initial process to the InitialProcessResolver after syscall number detection:

```
PS C:\Dev> .\InitialProcessResolver.exe -n ntcreateprocessex -d

[>] Trying to create initial process.
[+] Initial process is created successfully.
    [*] Process Name : svchost
    [*] Process ID   : 1336
[>] Trying to dump Nt API address.
[*] ntdll.dll @ 0x00007FFFB3350000
[+] Got 491 entries (Architecure: AMD64).
[+] NtCreateProcessEx @ 0x00007FFFB33EF700
[+] Syscall number for NtCreateProcessEx is 77 (0x4D).
[*] Debug break. To exit this program, hit [ENTER] key.
```

We can confirm that the syscall number for `NtCreateProcessEx` is 77 from output, and `svchost` process is created by InitialProcessResolver is 1336.
By scanning this `svchost` with ProcMemScan, we can see that the `svchost` process loads only ntdll.dll as follows:

```
PS C:\Dev> .\ProcMemScan.exe -p 1336 -l

[>] Trying to get target process memory information.
[*] Target process is 'svchost' (PID : 1336).
[+] Got target process memory information.

              Base           Size State       Protect                    Type        Mapped
0x0000000000000000     0x7FFE0000 MEM_FREE    PAGE_NOACCESS              NONE        N/A
0x000000007FFE0000         0x1000 MEM_COMMIT  PAGE_READONLY              MEM_PRIVATE N/A
0x000000007FFE1000         0xC000 MEM_FREE    PAGE_NOACCESS              NONE        N/A
0x000000007FFED000         0x1000 MEM_COMMIT  PAGE_READONLY              MEM_PRIVATE N/A
0x000000007FFEE000   0xBCE9C12000 MEM_FREE    PAGE_NOACCESS              NONE        N/A
0x000000BD69C00000        0x28000 MEM_RESERVE NONE                       MEM_PRIVATE N/A
0x000000BD69C28000         0x3000 MEM_COMMIT  PAGE_READWRITE             MEM_PRIVATE N/A
0x000000BD69C2B000       0x1D5000 MEM_RESERVE NONE                       MEM_PRIVATE N/A
0x000000BD69E00000        0x79000 MEM_RESERVE NONE                       MEM_PRIVATE N/A
0x000000BD69E79000         0x3000 MEM_COMMIT  PAGE_READWRITE, PAGE_GUARD MEM_PRIVATE N/A
0x000000BD69E7C000         0x4000 MEM_COMMIT  PAGE_READWRITE             MEM_PRIVATE N/A
0x000000BD69E80000  0x145FCB70000 MEM_FREE    PAGE_NOACCESS              NONE        N/A
0x00000203669F0000        0x20000 MEM_COMMIT  PAGE_READWRITE             MEM_PRIVATE N/A
0x0000020366A10000        0x1F000 MEM_COMMIT  PAGE_READONLY              MEM_MAPPED  N/A
0x0000020366A2F000 0x7BF1C9D61000 MEM_FREE    PAGE_NOACCESS              NONE        N/A
0x00007DF530790000         0x1000 MEM_COMMIT  PAGE_EXECUTE_READ          MEM_PRIVATE N/A
0x00007DF530791000         0xF000 MEM_FREE    PAGE_NOACCESS              NONE        N/A
0x00007DF5307A0000         0x1000 MEM_COMMIT  PAGE_READONLY              MEM_MAPPED  N/A
0x00007DF5307A1000         0xF000 MEM_FREE    PAGE_NOACCESS              NONE        N/A
0x00007DF5307B0000      0x1C67000 MEM_RESERVE NONE                       MEM_MAPPED  N/A
0x00007DF532417000         0x2000 MEM_COMMIT  PAGE_NOACCESS              MEM_MAPPED  N/A
0x00007DF532419000       0x165000 MEM_RESERVE NONE                       MEM_MAPPED  N/A
0x00007DF53257E000         0x1000 MEM_COMMIT  PAGE_NOACCESS              MEM_MAPPED  N/A
0x00007DF53257F000  0x1F7D2E4F000 MEM_RESERVE NONE                       MEM_MAPPED  N/A
0x00007FED053CE000         0x1000 MEM_COMMIT  PAGE_READONLY              MEM_MAPPED  N/A
0x00007FED053CF000    0x809C3D000 MEM_RESERVE NONE                       MEM_MAPPED  N/A
0x00007FF50F00C000         0x2000 MEM_COMMIT  PAGE_READONLY              MEM_MAPPED  N/A
0x00007FF50F00E000     0x1F049000 MEM_RESERVE NONE                       MEM_MAPPED  N/A
0x00007FF52E057000      0x1426000 MEM_COMMIT  PAGE_NOACCESS              MEM_MAPPED  N/A
0x00007FF52F47D000         0x9000 MEM_COMMIT  PAGE_READONLY              MEM_MAPPED  N/A
0x00007FF52F486000      0x132A000 MEM_RESERVE NONE                       MEM_MAPPED  N/A
0x00007FF5307B0000    0x270F80000 MEM_FREE    PAGE_NOACCESS              NONE        N/A
0x00007FF7A1730000         0x1000 MEM_COMMIT  PAGE_READONLY              MEM_IMAGE   C:\Windows\System32\svchost.exe
0x00007FF7A1731000         0x7000 MEM_COMMIT  PAGE_EXECUTE_READ          MEM_IMAGE   C:\Windows\System32\svchost.exe
0x00007FF7A1738000         0x4000 MEM_COMMIT  PAGE_READONLY              MEM_IMAGE   C:\Windows\System32\svchost.exe
0x00007FF7A173C000         0x1000 MEM_COMMIT  PAGE_WRITECOPY             MEM_IMAGE   C:\Windows\System32\svchost.exe
0x00007FF7A173D000         0x1000 MEM_COMMIT  PAGE_READONLY              MEM_IMAGE   C:\Windows\System32\svchost.exe
0x00007FF7A173E000         0x1000 MEM_COMMIT  PAGE_WRITECOPY             MEM_IMAGE   C:\Windows\System32\svchost.exe
0x00007FF7A173F000         0x2000 MEM_COMMIT  PAGE_READONLY              MEM_IMAGE   C:\Windows\System32\svchost.exe
0x00007FF7A1741000    0x811C0F000 MEM_FREE    PAGE_NOACCESS              NONE        N/A
0x00007FFFB3350000         0x1000 MEM_COMMIT  PAGE_READONLY              MEM_IMAGE   C:\Windows\System32\ntdll.dll
0x00007FFFB3351000       0x130000 MEM_COMMIT  PAGE_EXECUTE_READ          MEM_IMAGE   C:\Windows\System32\ntdll.dll
0x00007FFFB3481000        0x4D000 MEM_COMMIT  PAGE_READONLY              MEM_IMAGE   C:\Windows\System32\ntdll.dll
0x00007FFFB34CE000         0xC000 MEM_COMMIT  PAGE_WRITECOPY             MEM_IMAGE   C:\Windows\System32\ntdll.dll
0x00007FFFB34DA000         0xF000 MEM_COMMIT  PAGE_READONLY              MEM_IMAGE   C:\Windows\System32\ntdll.dll
0x00007FFFB34E9000         0x1000 MEM_COMMIT  PAGE_READWRITE             MEM_IMAGE   C:\Windows\System32\ntdll.dll
0x00007FFFB34EA000         0x3000 MEM_COMMIT  PAGE_WRITECOPY             MEM_IMAGE   C:\Windows\System32\ntdll.dll
0x00007FFFB34ED000        0x77000 MEM_COMMIT  PAGE_READONLY              MEM_IMAGE   C:\Windows\System32\ntdll.dll
0x00007FFFB3564000     0x4CA8C000 MEM_FREE    PAGE_NOACCESS              NONE        N/A

[*] Completed.

PS C:\Dev>
```

And `NtCreateProcessEx` code is not hooked:

```
PS C:\Dev> .\ProcMemScan.exe -p 1336 -d -b 0x00007FFFB33EF700 -r 20

[>] Trying to dump target process memory.
[*] Target process is 'svchost' (PID : 1336).
[+] Got target process memory.
    [*] BaseAddress       : 0x00007FFFB33EF000
    [*] AllocationBase    : 0x00007FFFB3350000
    [*] RegionSize        : 0x92000
    [*] AllocationProtect : PAGE_EXECUTE_WRITECOPY
    [*] State             : MEM_COMMIT
    [*] Protect           : PAGE_EXECUTE_READ
    [*] Type              : MEM_IMAGE
    [*] Mapped File Path  : C:\Windows\System32\ntdll.dll
    [*] Hexdump (0x20 Bytes):

                           00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F

        00007FFFB33EF700 | 4C 8B D1 B8 4D 00 00 00-F6 04 25 08 03 FE 7F 01 | L.Ñ,M... ö.%.._..
        00007FFFB33EF710 | 75 03 0F 05 C3 CD 2E C3-0F 1F 84 00 00 00 00 00 | u...AI.A ........


[*] Completed.

PS C:\Dev>
```


## Get-SyscallNumber.ps1

[Back to Top](#atomicsyscall)

[Script](./Get-SyscallNumber.ps1)

In this script, following 3 functions are implemented:

* __`Get-ModuleHandle`__ : As the name implies, this function resolve loaded module's base address as `GetModuleHandle` API.

* __`Get-ProcAddress`__ : As the name implies, this function resolve export function's address as `GetProcAddress` API.

* __`Get-SyscallNumber`__ : This function resolve syscall number with Hell's Gate or Halo's Gate technique.

If you want to resolve module base address such as `ntdll.dll`, set the module name as 1st arguments or `-ModuleName` option:

```
PS C:\> Import-Module C:\dev\Get-SyscallNumber.ps1
PS C:\> Get-ModuleHandle ntdll.dll
140720055189504
PS C:\> (140720055189504).ToString("X16")
00007FFBF0E70000
PS C:\> Get-ModuleHandle -ModuleName kernel32.dll
140720022028288
PS C:\> (140720022028288).ToString("X16")
00007FFBEEED0000
PS C:\>
```

To resolve export function address in a module, set base address of the module and export function name for `Get-ProcAddress` function.
The base address of the module should be specified with 1st argument or `-Module` option.
The export function name should be specified with 2nd argument or `-ProcName` option as follows:

```
PS C:\> $ntdll = Get-ModuleHandle -ModuleName ntdll.dll
PS C:\> Get-ProcAddress $ntdll NtCreateToken
140720055839008
PS C:\> (140720055839008).ToString("X16")
00007FFBF0F0E920
PS C:\> Get-ProcAddress -ProcName ntcreatetoken -Module $ntdll
140720055839008
PS C:\>
```

If you want to know syscall number, set the syscall name to 1st argument or `-SyscallName` option for `Get-SyscallNumber` function:

```
PS C:\> Get-SyscallNumber ntcreateuserprocess
Syscall Number : 0xC8
200
PS C:\> Get-SyscallNumber -SyscallName ntcreateprocessex
Syscall Number : 0x4D
77
PS C:\>
```

![getsyscallnumber.png](./figures/getsyscallnumber.png)


## Reference

[Back to Top](#atomicsyscall)

### Fundamentals

* [https://jhalon.github.io/utilizing-syscalls-in-csharp-1/](https://jhalon.github.io/utilizing-syscalls-in-csharp-1/)

* [https://jhalon.github.io/utilizing-syscalls-in-csharp-2/](https://jhalon.github.io/utilizing-syscalls-in-csharp-2/)

* [https://github.com/jhalon/SharpCall](https://github.com/jhalon/SharpCall)

### Heaven's Gate
* [https://wbenny.github.io/2018/11/04/wow64-internals.html](https://wbenny.github.io/2018/11/04/wow64-internals.html)

* [https://medium.com/@fsx30/hooking-heavens-gate-a-wow64-hooking-technique-5235e1aeed73](https://medium.com/@fsx30/hooking-heavens-gate-a-wow64-hooking-technique-5235e1aeed73)

* [https://mark.rxmsolutions.com/through-the-heavens-gate/](https://mark.rxmsolutions.com/through-the-heavens-gate/)

* [https://speakerdeck.com/aaaddress1/rebuild-the-heavens-gate-from-32-bit-hell-back-to-heaven-wonderland](https://speakerdeck.com/aaaddress1/rebuild-the-heavens-gate-from-32-bit-hell-back-to-heaven-wonderland)

* [http://blog.rewolf.pl/blog/?p=102](http://blog.rewolf.pl/blog/?p=102)

* [https://www.mandiant.com/resources/blog/wow64-subsystem-internals-and-hooking-techniques](https://www.mandiant.com/resources/blog/wow64-subsystem-internals-and-hooking-techniques)

* [https://www.malwaretech.com/2014/02/the-0x33-segment-selector-heavens-gate.html](https://www.malwaretech.com/2014/02/the-0x33-segment-selector-heavens-gate.html)

* [https://int0h.wordpress.com/2009/12/24/the-power-of-wow64/](https://int0h.wordpress.com/2009/12/24/the-power-of-wow64/)

* [https://modexp.wordpress.com/2015/11/19/dllpic-injection-on-windows-from-wow64-process/](https://modexp.wordpress.com/2015/11/19/dllpic-injection-on-windows-from-wow64-process/)

### Hell's Gate

* [https://vxug.fakedoma.in/papers/VXUG/Exclusive/HellsGate.pdf](https://vxug.fakedoma.in/papers/VXUG/Exclusive/HellsGate.pdf)

* [https://github.com/am0nsec/HellsGate](https://github.com/am0nsec/HellsGate)


### Halo's Gate

* [https://blog.sektor7.net/#!res/2021/halosgate.md](https://blog.sektor7.net/#!res/2021/halosgate.md)


### Acknowledgments

[Back to Top](#atomicsyscall)

Thanks for your research and blog posts:

* Paul Laîné ([@am0nsec](https://twitter.com/am0nsec))

* smelly__vx ([@smelly__vx](https://twitter.com/smelly__vx))

* reenz0h ([@sektor7net](https://twitter.com/sektor7net))

* Jack Halon ([@jack_halon](https://twitter.com/jack_halon))
