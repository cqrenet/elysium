function Restart-WithPwshIfAvailable {
    param(
        [hashtable]$BoundParameters,
        [object[]]$UnboundArguments
    )

    if ($PSVersionTable.PSVersion.Major -ge 7) { return }
    $pwsh = Get-Command -Name 'pwsh' -ErrorAction SilentlyContinue
    if (-not $pwsh) { return }
    if (-not $PSCommandPath) { return }

    Write-Host ("PowerShell 7 detected at '{0}'; relaunching script under pwsh..." -f $pwsh.Path)

    $argList = @('-NoLogo', '-NoProfile', '-File', $PSCommandPath)

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

    & $pwsh.Path @argList
    exit $LASTEXITCODE
}
