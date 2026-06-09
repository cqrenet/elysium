##################################################
##   ____ ___  ____  _____   _   _ _____ _____  ##
##  / ___/ _ \|  _ \| ____| | \ | | ____|_   _| ##
## | |  | | | | |_) |  _|   |  \| |  _|   | |   ##
## | |__| |_| |  _ <| |___ _| |\  | |___  | |   ##
##  \____\__\_\_| \_\_____(_)_| \_|_____| |_|   ##
##################################################
## Project: Elysium                             ##
## File: Uninstall.ps1                          ##
## Version: 2.2.3                               ##
## Support: support@cqre.net                    ##
##################################################

<#
.SYNOPSIS
Uninstall script for the Elysium AD password testing tool.

.DESCRIPTION
This script will remove the Elysium tool and its components (scripts, configurations, and any generated data) from the system, and then delete itself.
#>

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
[string]$commonHelper = Join-Path -Path $PSScriptRoot -ChildPath 'Elysium.Common.ps1'
if (-not (Test-Path -LiteralPath $commonHelper)) { throw "Common helper not found at $commonHelper" }
. $commonHelper
Restart-WithPwshIfAvailable -BoundParameters $PSBoundParameters -UnboundArguments $MyInvocation.UnboundArguments

function Start-UninstallTranscript {
    try {
        $base = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), 'Elysium', 'logs')
        if (-not (Test-Path $base)) { New-Item -Path $base -ItemType Directory -Force | Out-Null }
        $ts = Get-Date -Format 'yyyyMMdd-HHmmss'
        $logPath = Join-Path -Path $base -ChildPath "uninstall-$ts.log"
        Start-Transcript -Path $logPath -Force | Out-Null
    } catch {
        Write-Warning "Could not start transcript: $($_.Exception.Message)"
    }
}

function Stop-UninstallTranscript { try { Stop-Transcript | Out-Null } catch {} }

function Uninstall-Elysium {
    $ElysiumPath = Get-Location

    Write-Host "Uninstalling Elysium tool from $ElysiumPath..."

    # Check if the Elysium directory exists
    if (Test-Path $ElysiumPath) {
        # Schedule the script file for deletion
        $scriptPath = $MyInvocation.MyCommand.Path
        $deleteScript = { param($path) Remove-Item -Path $path -Force }
        Start-Sleep -Seconds 3 # Delay to ensure the script finishes
        Start-Process -FilePath "powershell.exe" -ArgumentList "-Command", $deleteScript, "-ArgumentList", $scriptPath -WindowStyle Hidden

        # Remove the Elysium directory and all its contents
        Remove-Item -Path $ElysiumPath -Recurse -Force -Exclude $scriptPath
        Write-Host "Elysium tool and all related files have been removed, excluding this script. This script will be deleted shortly."
    } else {
        Write-Host "Elysium directory not found. It might have been removed already, or the path is incorrect."
    }

    # Additional cleanup actions can be added here if needed
}

Start-UninstallTranscript
try {
    # Execute the uninstall function
    Uninstall-Elysium

# Check if the Elysium passphrase environment variable exists
$passphraseEnvVar = [System.Environment]::GetEnvironmentVariable("ELYSIUM_PASSPHRASE", [System.EnvironmentVariableTarget]::User)

if ([string]::IsNullOrEmpty($passphraseEnvVar)) {
    Write-Host "No passphrase environment variable to remove."
} else {
    # Remove the Elysium passphrase environment variable
    [System.Environment]::SetEnvironmentVariable("ELYSIUM_PASSPHRASE", $null, [System.EnvironmentVariableTarget]::User)
    Write-Host "Elysium passphrase environment variable has been removed."
}

# Confirm uninstallation
Write-Host "Elysium tool has been successfully uninstalled. Exiting script." -ForegroundColor Green
} finally {
    Stop-UninstallTranscript
}
