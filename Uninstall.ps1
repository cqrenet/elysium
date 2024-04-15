##################################################
##   ____ ___  ____  _____   _   _ _____ _____  ##
##  / ___/ _ \|  _ \| ____| | \ | | ____|_   _| ##
## | |  | | | | |_) |  _|   |  \| |  _|   | |   ##
## | |__| |_| |  _ <| |___ _| |\  | |___  | |   ##
##  \____\__\_\_| \_\_____(_)_| \_|_____| |_|   ##
##################################################
## Project: Elysium                             ##
## File: Uninstall.ps1                          ##
## Version: 1.0.0                               ##
## Support: support@cqre.net                    ##
##################################################

<#
.SYNOPSIS
Uninstall script for the Elysium AD password testing tool.

.DESCRIPTION
This script will remove the Elysium tool and its components (scripts, configurations, and any generated data) from the system, and then delete itself.
#>

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
