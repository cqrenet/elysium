##################################################
##   ____ ___  ____  _____   _   _ _____ _____  ##
##  / ___/ _ \|  _ \| ____| | \ | | ____|_   _| ##
## | |  | | | | |_) |  _|   |  \| |  _|   | |   ##
## | |__| |_| |  _ <| |___ _| |\  | |___  | |   ##
##  \____\__\_\_| \_\_____(_)_| \_|_____| |_|   ##
##################################################
## Project: Elysium                             ##
## File: Uninstall.ps1                          ##
## Version: 2.4.6                               ##
## Support: support@cqre.net                    ##
##################################################

<#
.SYNOPSIS
Uninstall script for the Elysium AD password testing tool.

.DESCRIPTION
This script will remove the Elysium tool and its components (scripts, configurations, and any generated data) from the system, and then delete itself.

.PARAMETER Force
Skip the confirmation prompt (for unattended removal).
#>

param([switch]$Force)

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
    $ElysiumPath = $PSScriptRoot

    Write-Host "Uninstalling Elysium tool from $ElysiumPath..."

    # Check if the Elysium directory exists
    if (Test-Path $ElysiumPath) {
        # PowerShell reads the whole script into memory before execution begins, so it holds no
        # open file handle on this script - deleting the install directory (including this file)
        # while still running is safe and needs no deferred external delete process.
        Remove-Item -Path $ElysiumPath -Recurse -Force
        Write-Host "Elysium tool and all related files have been removed."
    } else {
        Write-Host "Elysium directory not found. It might have been removed already, or the path is incorrect."
    }
}

Start-UninstallTranscript
try {
    # The delete is recursive and irreversible (reports, KHDB, settings included), so a mistyped
    # menu choice or a stale doc reference must not be enough to trigger it.
    if (-not $Force) {
        $answer = Read-Host "This permanently deletes '$PSScriptRoot' including all reports, the KHDB and settings. Type YES to continue"
        if ($answer -cne 'YES') {
            Write-Host 'Uninstall cancelled.'
            return
        }
    }

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
