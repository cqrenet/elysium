# pwsh <-> Windows PowerShell relaunch helpers, called by the root scripts before they do any work.

function Invoke-RestartWithExecutable {
    param(
        [string]$ExecutablePath,
        [string]$ScriptPath,
        [hashtable]$BoundParameters,
        [object[]]$UnboundArguments
    )

    if (-not $ExecutablePath) { return }
    if (-not $ScriptPath) { return }

    $argList = @('-NoLogo', '-NoProfile', '-File', $ScriptPath)

    if ($BoundParameters) {
        foreach ($entry in $BoundParameters.GetEnumerator()) {
            $key = "-$($entry.Key)"
            $value = $entry.Value
            if ($value -is [System.Management.Automation.SwitchParameter]) {
                if ($value.IsPresent) { $argList += $key }
            } else {
                $argList += $key
                $argList += $value
            }
        }
    }

    if ($UnboundArguments) {
        $argList += $UnboundArguments
    }

    & $ExecutablePath @argList
    exit $LASTEXITCODE
}

function Restart-WithPwshIfAvailable {
    param(
        [hashtable]$BoundParameters,
        [object[]]$UnboundArguments
    )

    if ($PSVersionTable.PSVersion.Major -ge 7 -or $PSVersionTable.PSEdition -eq 'Core') { return }
    $pwsh = Get-Command -Name 'pwsh' -ErrorAction SilentlyContinue
    if (-not $pwsh) { return }
    Write-Host ("PowerShell 7 detected at '{0}'; relaunching script under pwsh..." -f $pwsh.Path)
    # $PSCommandPath here would be this helper file (where the function is defined), not the
    # script being relaunched; $MyInvocation.PSCommandPath is the script that called us.
    Invoke-RestartWithExecutable -ExecutablePath $pwsh.Path -ScriptPath $MyInvocation.PSCommandPath -BoundParameters $BoundParameters -UnboundArguments $UnboundArguments
}

function Restart-WithWindowsPowerShellIfAvailable {
    param(
        [hashtable]$BoundParameters,
        [object[]]$UnboundArguments
    )

    if ($PSVersionTable.PSEdition -eq 'Desktop') { return }
    $powershellCmd = Get-Command -Name 'powershell.exe' -ErrorAction SilentlyContinue
    $powershellPath = $null
    if ($powershellCmd) {
        $powershellPath = $powershellCmd.Path
    } else {
        $defaultPath = Join-Path -Path $env:SystemRoot -ChildPath 'System32\WindowsPowerShell\v1.0\powershell.exe'
        if (Test-Path -LiteralPath $defaultPath) {
            $powershellPath = $defaultPath
        }
    }
    if (-not $powershellPath) {
        Write-Warning 'Windows PowerShell (powershell.exe) was not found; continuing under current host.'
        return
    }
    Write-Host ("Windows PowerShell detected at '{0}'; relaunching script under powershell.exe..." -f $powershellPath)
    Invoke-RestartWithExecutable -ExecutablePath $powershellPath -ScriptPath $MyInvocation.PSCommandPath -BoundParameters $BoundParameters -UnboundArguments $UnboundArguments
}
