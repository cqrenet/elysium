# Windows PowerShell relaunch for the AD wrappers (Test-WeakADPasswords.ps1, Extract-NTHashes.ps1),
# which dot-source this file before importing the module: DSInternals/ActiveDirectory need Desktop.

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
