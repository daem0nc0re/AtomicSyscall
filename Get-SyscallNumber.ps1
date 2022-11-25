function Get-ModuleHandle {
    Param(
        [OutputType([IntPtr])]

        [Parameter(Mandatory = $true, Position = 0)]
        [string]$ModuleName
    )

    $baseAddress = [IntPtr]::Zero
    $modules = [System.Diagnostics.Process]::GetCurrentProcess().Modules

    foreach ($mod in $modules) {
        if ($mod.ModuleName -ieq $ModuleName) {
            $baseAddress = $mod.BaseAddress
            break
        }
    }

    $baseAddress
}


function Get-ProcAddress {
    Param(
        [OutputType([IntPtr])]

        [Parameter(Mandatory = $true, Position = 0)]
        [IntPtr]$Module,

        [Parameter(Mandatory = $true, Position = 1)]
        [string]$ProcName
    )

    $functionAddress = [IntPtr]::Zero
    $export_dir = [IntPtr]::Zero
    $numberOfNames = 0
    $addressOfFunctions = [IntPtr]::Zero
    $addressOfNames = [IntPtr]::Zero
    $addressOfNameOrdinals = [IntPtr]::Zero
    $namePointer = [IntPtr]::Zero
    $index = 0

    if ([System.Runtime.InteropServices.Marshal]::ReadInt16($Module) -ne 0x5A4D) {
        return $functionAddress
    }

    if ([IntPtr]::Size -eq 8) {
        $e_lfanew = [System.Runtime.InteropServices.Marshal]::ReadInt32($Module.ToInt64() + 0x3C)
        $virtual_address = [System.Runtime.InteropServices.Marshal]::ReadInt32($Module.ToInt64() + $e_lfanew + 0x18 + 0x70)
        $export_dir = [IntPtr]($Module.ToInt64() + $virtual_address)
        $numberOfNames = [System.Runtime.InteropServices.Marshal]::ReadInt32($export_dir.ToInt64() + 0x18)
        $addressOfFunctions = [IntPtr]($Module.ToInt64() + [System.Runtime.InteropServices.Marshal]::ReadInt32($export_dir.ToInt64() + 0x1C))
        $addressOfNames = [IntPtr]($Module.ToInt64() + [System.Runtime.InteropServices.Marshal]::ReadInt32($export_dir.ToInt64() + 0x20))
        $addressOfNameOrdinals = [IntPtr]($Module.ToInt64() + [System.Runtime.InteropServices.Marshal]::ReadInt32($export_dir.ToInt64() + 0x24))
    } else {
        $e_lfanew = [System.Runtime.InteropServices.Marshal]::ReadInt32($Module.ToInt32() + 0x3C)
        $virtual_address = [System.Runtime.InteropServices.Marshal]::ReadInt32($Module.ToInt32() + $e_lfanew + 0x18 + 0x60)
        $export_dir = [IntPtr]($Module.ToInt32() + $virtual_address)
        $numberOfNames = [System.Runtime.InteropServices.Marshal]::ReadInt32($export_dir.ToInt32() + 0x18)
        $addressOfFunctions = [IntPtr]($Module.ToInt32() + [System.Runtime.InteropServices.Marshal]::ReadInt32($export_dir.ToInt32() + 0x1C))
        $addressOfNames = [IntPtr]($Module.ToInt32() + [System.Runtime.InteropServices.Marshal]::ReadInt32($export_dir.ToInt32() + 0x20))
        $addressOfNameOrdinals = [IntPtr]($Module.ToInt32() + [System.Runtime.InteropServices.Marshal]::ReadInt32($export_dir.ToInt32() + 0x24))
    }

    for ($counter = 0; $counter -lt $numberOfNames; $counter++) {
        if ([IntPtr]::Size -eq 8) {
            $namePointer = [IntPtr]($Module.ToInt64() + [System.Runtime.InteropServices.Marshal]::ReadInt32($addressOfNames.ToInt64() + (4 * $counter)))
        } else {
            $namePointer = [IntPtr]($Module.ToInt32() + [System.Runtime.InteropServices.Marshal]::ReadInt32($addressOfNames.ToInt32() + (4 * $counter)))
        }

        $entryName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($namePointer)

        if ($entryName -ieq $ProcName) {
            $index = $counter
            break
        }
    }

    if ($index -ne 0) {
        if ([IntPtr]::Size -eq 8) {
            $ordinal = [System.Runtime.InteropServices.Marshal]::ReadInt16($addressOfNameOrdinals.ToInt64() + (2 * $index))
            $offset = [System.Runtime.InteropServices.Marshal]::ReadInt32($addressOfFunctions.ToInt64() + (4 * $ordinal))
            $functionAddress = [IntPtr]($Module.ToInt64() + $offset)
        }
        else {
            $ordinal = [System.Runtime.InteropServices.Marshal]::ReadInt16($addressOfNameOrdinals.ToInt32() + (2 * $index))
            $offset = [System.Runtime.InteropServices.Marshal]::ReadInt32($addressOfFunctions.ToInt32() + (4 * $ordinal))
            $functionAddress = [IntPtr]($Module.ToInt32() + $offset)
        }
    }

    $functionAddress
}


function Get-SyscallNumber {
    Param(
        [OutputType([Int32])]

        [Parameter(Mandatory = $true, Position = 0)]
        [string]$SyscallName
    )

    $moduleName = $null
    $syscallNumber = -1;

    if ($SyscallName -match "^NtGdi\S+$") {
        $moduleName = "win32u.dll"
    } elseif ($SyscallName -match "^Nt\S+$") {
        $moduleName = "ntdll.dll"
    } else {
        Write-Warning "Syscall name should be start with `"Nt`" or `"NtGdi`"."

        return -1
    }

    $moduleBase = Get-ModuleHandle $moduleName

    if ($moduleBase -eq [IntPtr]::Zero) {
        Write-Warning "Failed to resolve module base."

        return -1
    }

    $functionBase = Get-ProcAddress $moduleBase $SyscallName

    if ($functionBase -eq [IntPtr]::Zero) {
        Write-Warning "Failed to resolve the specified syscall name."

        return -1
    }

    $architecture = [System.Environment]::GetEnvironmentVariable("PROCESSOR_ARCHITECTURE")

    if ($architecture -ieq "x86") {
        $isArm = [System.IO.Directory]::Exists("C:\Windows\SysArm32")

        for ($count = 0; $count -lt 0x10; $count++) {
            if ([System.Runtime.InteropServices.Marshal]::ReadByte($functionBase) -eq 0xB8) { # mov eax, 0x????
                $syscallNumber = [System.Runtime.InteropServices.Marshal]::ReadInt32($functionBase, 1) + $count

                break;
            } else {
                if ($isArm) {
                    $functionBase = [IntPtr]($functionBase.ToInt32() - 0x10)
                } else {
                    $functionBase = [IntPtr]($functionBase.ToInt32() - 0x20)
                }
            }
        }
    } elseif ($architecture -ieq "AMD64") {
        for ($count = 0; $count -lt 0x10; $count++) {
            if ([System.Runtime.InteropServices.Marshal]::ReadInt32($functionBase) -eq 0xB8D18B4C) { # mov r10, rcx; mov eax, 0x???? 
                $syscallNumber = [System.Runtime.InteropServices.Marshal]::ReadInt32($functionBase, 4) + $count

                break;
            } else {
                $functionBase = [IntPtr]($functionBase.ToInt64() - 0x20)
            }
        }
    } elseif ($architecture -ieq "ARM64") {
        for ($count = 0; $count -lt 0x10; $count++) {
            $instruction = [System.Runtime.InteropServices.Marshal]::ReadInt32($functionBase)

            if (($instruction -band 0xFFE0001F) -eq 0xD4000001) { # svc #0x??
                $syscallNumber = (($instruction -shr 5) -band 0x0000FFFF) + $count

                break;
            } else {
                $functionBase = [IntPtr]($functionBase.ToInt64() - 0x10)
            }
        }
    } else {
        Write-Warning "Unsupported architecture."

        return -1
    }

    if ($syscallNumber -ne -1) {
        Write-Host "Syscall Number : 0x$($syscallNumber.ToString("X"))"
    }

    $syscallNumber
}
