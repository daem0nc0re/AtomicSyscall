# HeavensGate

This directory is for Heaven's Gate technique.

## HeavensGatePoC

[Project](./HeavensGatePoC)

Using Heaven's Gate technique, this PoC tries to dump `ntdll!_PEB64` information from 32bit process by calling 64bit shellcode and `NtReadVirtualMemory` syscall.