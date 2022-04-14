# AtomicSyscall
Tools and PoCs for Windows syscall investigation.


## Table Of Contents

- [AtomicSyscall](#atomicsyscall)
  - [SyscallDumper](#syscalldumper)
  - [SyscallPoCs](#syscallpocs)
  - [SyscallResolvers](#syscallresolvers)
  - [Reference](#reference)
  - [Acknowledgments](#acknowledgments)


## SyscallDumper

[Back to Top](#atomicsyscall)

[Project](./SyscallDumper)

This tool is to dump Windows syscall from ntdll.dll or win32u.dll:

```
C:\Tools>SyscallDumper.exe


SyscallDumper - Tool to dump syscall.

Usage: SyscallDumper.exe [Options] [INPUT_DLL_1] [INPUT_DLL_2]

        -h, --help   : Displays this help message.
        -d, --dump   : Flag to dump syscall from ntdll.dll or win32u.dll.
        -D, --diff   : Flag to take diff between 2 dlls.
        -f, --filter : Specifies search filter (e.g. "-f createfile").
        -o, --output : Specifies output file (e.g. "-o result.txt").
        INPUT_DLL_1  : Specifies path of ntdll.dll or win32u.dll. Older one in diffing.
        INPUT_DLL_2  : Specifies path of ntdll.dll or win32u.dll. Newer one in diffing.


[!] Should be specified -d or -D option.
```

To dump syscall numbers from ntdll.dll or win32u.dll, use `-d` (`--dump`) option.
If you don't specifies source DLL, this tool dumps syscall numbers from `C:\Windows\System32\ntdll.dll` and `C:\Windows\System32\win32u.dll`:

```
C:\Tools>SyscallDumper.exe -d

[*] No target is specified.
[>] Dumping from system default ntdll.dll and win32u.dll.
[>] Loading C:\Windows\System32\ntdll.dll.
[+] C:\Windows\System32\ntdll.dll is loaded successfully.
    |-> Architecture : x64
    |-> Image Name   : ntdll.dll
[+] Got 463 syscall(s).
[>] Loading C:\Windows\System32\win32u.dll.
[+] C:\Windows\System32\win32u.dll is loaded successfully.
    |-> Architecture : x64
    |-> Image Name   : win32u.dll
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

If you want to filter syscall name from dump result, use `-f` (`--filter`) option.
And you can save result to a file with `-o` (`--output`) option as follows:

```
C:\Tools>SyscallDumper.exe -d C:\SyscallSamples\1809x64\ntdll.dll -f token -o result.txt

[>] Loading C:\SyscallSamples\1809x64\ntdll.dll.
[+] C:\SyscallSamples\1809x64\ntdll.dll is loaded successfully.
    |-> Architecture : x64
    |-> Image Name   : ntdll.dll
[+] Got 462 syscall(s).
[>] Trying to save results.
    |-> Output File Path : c:\Tools\result.txt
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

To take difference between 2 DLL's syscall tables, use `-D` (`--diff`) option as follows:

```
C:\Tools>SyscallDumper.exe -D C:\dev\SyscallSamples\1809x64\win32u.dll C:\dev\SyscallSamples\1903x64\win32u.dll

[>] Trying to take diff.
    |-> Old File : C:\dev\SyscallSamples\1809x64\win32u.dll
    |-> New File : C:\dev\SyscallSamples\1903x64\win32u.dll
[>] Loading C:\dev\SyscallSamples\1809x64\win32u.dll.
[+] C:\dev\SyscallSamples\1809x64\win32u.dll is loaded successfully.
    |-> Architecture : x64
    |-> Image Name   : win32u.dll
[+] Got 1242 syscall(s).
[>] Loading C:\dev\SyscallSamples\1903x64\win32u.dll.
[+] C:\dev\SyscallSamples\1903x64\win32u.dll is loaded successfully.
    |-> Architecture : x64
    |-> Image Name   : win32u.dll
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

The following figure shows the difference between Hell's Gate and Halo's Gate in anti-virus software installed environment.
Hell's Gate technique does not work for patched `NtCreateProcessEx` function.
On the other hand, Halo's Gate technique works for patched `NtCreateProcessEx` function:

![syscallresolvers.png](./figures/syscallresolvers.png)


## Reference

[Back to Top](#atomicsyscall)

### Fundamentals

* [https://jhalon.github.io/utilizing-syscalls-in-csharp-1/](https://jhalon.github.io/utilizing-syscalls-in-csharp-1/)

* [https://jhalon.github.io/utilizing-syscalls-in-csharp-2/](https://jhalon.github.io/utilizing-syscalls-in-csharp-2/)

* [https://github.com/jhalon/SharpCall](https://github.com/jhalon/SharpCall)


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
