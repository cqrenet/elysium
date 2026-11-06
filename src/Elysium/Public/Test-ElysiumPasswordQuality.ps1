function Test-ElysiumPasswordQuality {
    <#
    .SYNOPSIS
    Tests AD account passwords against the KHDB with DSInternals and writes a weak-password report.

    .DESCRIPTION
    Uses the domain from ElysiumSettings.txt named by -Domain (or prompts for one) and the credentials in
    -Credential (or prompts for credentials with replication rights), pre-checks
    the credentials, DC clock skew and replication permissions, replicates accounts with Get-ADReplAccount
    and runs Test-PasswordQuality against the KHDB. Writes a text report and a UPN-only list of dictionary
    hits under ReportPathBase. Windows only; under PowerShell 7 the ActiveDirectory and DSInternals
    modules are loaded through Windows PowerShell compatibility.

    .PARAMETER Domain
    Name of a configured domain (DomainNName in ElysiumSettings.txt). Omit to choose interactively.

    .PARAMETER Credential
    Account with the replication rights. Omit to be prompted (the prompt validates against the DC).
    #>
    [CmdletBinding()]
    param(
        [string]$Domain,
        [System.Management.Automation.PSCredential]$Credential
    )

    # Current timestamp for both report generation and header
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

    # Define Header and Footer for the report with dynamic date
    $header = @"
=========== Elysium Report ==========
Report Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
=====================================

"@
    $footer = "`r`n==== End of Report ===="

    Start-ElysiumTranscript -BasePath $InstallRoot -Name 'test-weakad'
    try {
        Write-Verbose "Loading settings..."
        $ElysiumSettings = Read-ElysiumSettings -ScriptRoot $InstallRoot
        Write-Verbose "Settings loaded successfully."

        $usageBeaconUrl = $ElysiumSettings['UsageBeaconUrl']
        $usageBeaconMethod = $ElysiumSettings['UsageBeaconMethod']
        $usageBeaconInstanceId = $ElysiumSettings['UsageBeaconInstanceId']
        $usageBeaconTimeoutSeconds = $null
        if ($ElysiumSettings.ContainsKey('UsageBeaconTimeoutSeconds')) {
            $parsedTimeout = 0
            if ([int]::TryParse($ElysiumSettings['UsageBeaconTimeoutSeconds'], [ref]$parsedTimeout)) {
                $usageBeaconTimeoutSeconds = $parsedTimeout
            }
        }
        if (-not [string]::IsNullOrWhiteSpace($usageBeaconUrl)) {
            $beaconParams = @{ Url = $usageBeaconUrl }
            if (-not [string]::IsNullOrWhiteSpace($usageBeaconMethod)) {
                $beaconParams['Method'] = $usageBeaconMethod
            }
            if (-not [string]::IsNullOrWhiteSpace($usageBeaconInstanceId)) {
                $beaconParams['InstanceId'] = $usageBeaconInstanceId
            }
            if ($null -ne $usageBeaconTimeoutSeconds) {
                $beaconParams['TimeoutSeconds'] = $usageBeaconTimeoutSeconds
            }
            Invoke-UsageBeacon @beaconParams
        }

        # Continue with script logic...
        $domainDetails = Get-DomainDetailsFromSettings -Settings $ElysiumSettings
        Write-Verbose ("Domain details extracted: {0}" -f ($domainDetails | ConvertTo-Json))

        # Import required modules with PowerShell 7 compatibility
        # - On Windows PowerShell: Import normally
        # - On PowerShell 7+ on Windows: Import using -UseWindowsPowerShell if available
        # - On non-Windows Core: not supported for AD/DSInternals
        $runningInPSCore = ($PSVersionTable.PSEdition -eq 'Core')
        $onWindows = ($env:OS -match 'Windows') -or ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT)
        try { $osProductType = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).ProductType } catch { $osProductType = 1 }
        $isServerOS = $onWindows -and ($osProductType -ne 1)

        if ($runningInPSCore -and -not $onWindows) {
            throw 'This script requires Windows when running under PowerShell 7 (AD/DSInternals are Windows-only).'
        }

        if (Test-IsFipsPolicyEnabled) {
            throw @"
FIPS policy is enabled on this host (HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy\Enabled = 1).
Test-WeakADPasswords uses DSInternals/AD replication operations that are not fully compatible with this policy in this environment.

Remediation:
1. Run this script from a dedicated non-FIPS workstation/jump host.
2. If approved by your security policy, temporarily disable local FIPS policy for this host, run the test, then re-enable it.
3. If FIPS must remain enforced, use an alternative fully FIPS-validated workflow/tool for weak password assessment.
"@
        }

        try {
            Import-CompatModule -Name 'ActiveDirectory'
        } catch {
            Write-Warning ("ActiveDirectory import failed: {0}" -f $_.Exception.Message)
            if (Ensure-ADModule) {
                Import-CompatModule -Name 'ActiveDirectory'
            } else {
                throw "Failed to import ActiveDirectory module. On PS7, ensure RSAT AD tools are installed and Windows PowerShell 5.1 is present."
            }
        }

        try {
            Import-CompatModule -Name 'DSInternals'
        } catch {
            Write-Warning ("DSInternals import failed: {0}" -f $_.Exception.Message)
            if (Ensure-DSInternalsModule) {
                Import-CompatModule -Name 'DSInternals'
            } else {
                throw "Failed to import DSInternals module. Try installing from PSGallery or placing it under '$env:ProgramFiles\WindowsPowerShell\Modules'."
            }
        }

        # Version check: v6.2 was unsigned (blocks native DLLs, causes replication failures);
        # v7.0 fixes intermittent CRC errors mid-replication and Test-PasswordQuality result truncation.
        $dsInternalsVersion = (Get-Module -Name DSInternals).Version
        $minimumVersion = [version]'7.0'
        $unsignedVersion = [version]'6.2'
        if ($dsInternalsVersion -eq $unsignedVersion) {
            Write-Warning ("DSInternals {0} is not digitally signed, which blocks its native DLLs and causes replication failures. Update to v7.0+: Install-Module DSInternals -Force -AllowClobber" -f $dsInternalsVersion)
        } elseif ($dsInternalsVersion -lt $minimumVersion) {
            $resp = Read-Host ("DSInternals {0} is installed; v7.0 fixes intermittent replication CRC errors and result truncation. Update now? [Y/N]" -f $dsInternalsVersion)
            if ($resp -match '^(?i:y|yes)$') {
                try {
                    # Install-Module -Force is used instead of Update-Module to avoid a PowerShellGet bug
                    # where null PublishedDate metadata causes "cannot convert null to type system.datetime"
                    Install-Module -Name DSInternals -Force -AllowClobber -ErrorAction Stop
                    Write-Host '[+] DSInternals updated. Please re-run the script to load the new version.'
                    return
                } catch {
                    Write-Warning ("DSInternals update failed: {0}" -f $_.Exception.Message)
                }
            }
        }

        $WeakHashesSortedFilePath = Get-KhdbPath $ElysiumSettings
        if (-not (Test-Path $WeakHashesSortedFilePath)) {
            Write-Error "Weak password hashes file not found at '$WeakHashesSortedFilePath'."
            return
        }
        Write-Verbose "Weak password hashes file found at '$WeakHashesSortedFilePath'."

        # Ensure the report directory exists (relative paths resolved against script root)
        $reportPathBase = $ElysiumSettings["ReportPathBase"]
        if ([string]::IsNullOrWhiteSpace($reportPathBase)) { $reportPathBase = 'Reports' }
        if (-not [System.IO.Path]::IsPathRooted($reportPathBase)) { $reportPathBase = Join-Path -Path $InstallRoot -ChildPath $reportPathBase }
        if (-not (Test-Path -Path $reportPathBase)) {
            try {
                New-Item -Path $reportPathBase -ItemType Directory -ErrorAction Stop | Out-Null
                Write-Verbose "Report directory created at '$reportPathBase'."
            } catch {
                Write-Error ("Failed to create report directory: {0}" -f $_.Exception.Message)
                return
            }
        }

        # Read filtering flag (defaults to false)
        $checkOnlyEnabledUsers = $false
        if ($ElysiumSettings.ContainsKey('CheckOnlyEnabledUsers')) {
            try { $checkOnlyEnabledUsers = [System.Convert]::ToBoolean($ElysiumSettings['CheckOnlyEnabledUsers']) } catch { $checkOnlyEnabledUsers = $false }
        }

        # Window that separates a live filter gap from legacy backlog in the report (defaults to 180 days).
        $recentPasswordWindowDays = 180
        if ($ElysiumSettings.ContainsKey('RecentPasswordWindowDays')) {
            $parsedWindow = 0
            if ([int]::TryParse($ElysiumSettings['RecentPasswordWindowDays'], [ref]$parsedWindow) -and $parsedWindow -gt 0) {
                $recentPasswordWindowDays = $parsedWindow
            }
        }

        # Main script logic
        Write-Verbose "Starting main script execution..."
        Invoke-WeakPasswordTest -DomainDetails $domainDetails -FilePath $WeakHashesSortedFilePath -CheckOnlyEnabledUsers:$checkOnlyEnabledUsers -DomainName $Domain -Credential $Credential -RecentPasswordWindowDays $recentPasswordWindowDays
    } catch {
        Write-Error ("An error occurred during script execution: {0}" -f $_.Exception.Message)
    } finally {
        Stop-ElysiumTranscript
    }
}
