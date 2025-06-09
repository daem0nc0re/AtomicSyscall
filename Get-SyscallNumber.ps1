function Get-ModuleHandle {
    Param (
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
    Param (
        [OutputType([IntPtr])]

        [Parameter(Mandatory = $true, Position = 0)]
        [IntPtr]$Module,

        [Parameter(Mandatory = $true, Position = 1)]
        [string]$ProcName
    )

    $routineBase = [IntPtr]::Zero
    $directoryOffset = 0
    $e_lfanew = [System.Runtime.InteropServices.Marshal]::ReadInt32($Module, 0x3C)

    if ([System.Runtime.InteropServices.Marshal]::ReadInt16($Module) -ne 0x5A4D) {
        return [IntPtr]::Zero
    }

    if ([IntPtr]::Size -eq 8) {
        $directoryOffset = [System.Runtime.InteropServices.Marshal]::ReadInt32($Module, $e_lfanew + 0x88)
    } else {
        $directoryOffset = [System.Runtime.InteropServices.Marshal]::ReadInt32($Module, $e_lfanew + 0x78)
    }

    if ($directoryOffset -eq 0) {
        return [IntPtr]::Zero
    }

    $numberOfNames = [System.Runtime.InteropServices.Marshal]::ReadInt32($Module, $directoryOffset + 0x18)
    $addressOfFunctions = [System.Runtime.InteropServices.Marshal]::ReadInt32($Module, $directoryOffset + 0x1C)
    $addressOfNames = [System.Runtime.InteropServices.Marshal]::ReadInt32($Module, $directoryOffset + 0x20)
    $addressOfNameOrdinals = [System.Runtime.InteropServices.Marshal]::ReadInt32($Module, $directoryOffset + 0x24)

    for ($counter = 0; $counter -lt $numberOfNames; $counter++) {
        $offset = [System.Runtime.InteropServices.Marshal]::ReadInt32($Module, $addressOfNames + (4 * $counter))

        if ([IntPtr]::Size -eq 8) {
            $namePointer = [IntPtr]::new($Module.ToInt64() + [UInt32]$offset)
        } else {
            $namePointer = [IntPtr]::new($Module.ToInt32() + $offset)
        }

        $exportName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($namePointer)

        if ($exportName -ieq $ProcName) {
            $ordinal = [System.Runtime.InteropServices.Marshal]::ReadInt16($Module, $addressOfNameOrdinals + (2 * $counter))
            $offset = [System.Runtime.InteropServices.Marshal]::ReadInt32($Module, $addressOfFunctions + (4 * $ordinal))

            if ([IntPtr]::Size -eq 8) {
                $routineBase = [IntPtr]::new($Module.ToInt64() + [UInt32]$offset)
            } else {
                $routineBase = [IntPtr]::new($Module.ToInt32() + $offset)
            }

            break
        }
    }

    $routineBase
}


function Get-SyscallNumber {
    Param (
        [OutputType([Int32])]

        [Parameter(Mandatory = $true, Position = 0)]
        [string]$SyscallName
    )

    $moduleNames = @("ntdll.dll", "win32u.dll")
    $moduleName = $null
    $syscallNumber = -1;

    if ($SyscallName -notmatch "^Nt\S+$") {
        Write-Warning "Syscall name should be start with `"Nt`"."

        return -1
    }

    foreach ($moduleName in $moduleNames) {
        $moduleBase = Get-ModuleHandle $moduleName

        if ($moduleBase -eq [IntPtr]::Zero) {
            Write-Warning "Failed to resolve module base."
            break
        }

        $functionBase = Get-ProcAddress $moduleBase $SyscallName

        if ($functionBase -eq [IntPtr]::Zero) {
            continue
        }

        $architecture = [System.Environment]::GetEnvironmentVariable("PROCESSOR_ARCHITECTURE")

        if ($architecture -ieq "x86") {
            $isArm = [System.IO.Directory]::Exists("C:\Windows\SysArm32")

            for ($count = 0; $count -lt 0x10; $count++) {
                if ([System.Runtime.InteropServices.Marshal]::ReadByte($functionBase) -eq 0xB8) { # mov eax, 0x????
                    $syscallNumber = [System.Runtime.InteropServices.Marshal]::ReadInt32($functionBase, 1) + $count
                    break
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
                    break
                } else {
                    $functionBase = [IntPtr]($functionBase.ToInt64() - 0x20)
                }
            }
        } elseif ($architecture -ieq "ARM64") {
            for ($count = 0; $count -lt 0x10; $count++) {
                $instruction = [System.Runtime.InteropServices.Marshal]::ReadInt32($functionBase)

                if (($instruction -band 0xFFE0001F) -eq 0xD4000001) { # svc #0x??
                    $syscallNumber = (($instruction -shr 5) -band 0x0000FFFF) + $count
                    break
                } else {
                    $functionBase = [IntPtr]($functionBase.ToInt64() - 0x10)
                }
            }
        } else {
            Write-Warning "Unsupported architecture."
            break
        }

        if ($syscallNumber -ne -1) {
            break
        }
    }

    if ($functionBase -eq [IntPtr]::Zero) {
        Write-Warning "Failed to resolve the specified syscall name."
    }

    if ($syscallNumber -ne -1) {
        Write-Host "Syscall Number : 0x$($syscallNumber.ToString("X"))"
    }

    $syscallNumber
}
