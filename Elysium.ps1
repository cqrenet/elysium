##################################################
##   ____ ___  ____  _____   _   _ _____ _____  ##
##  / ___/ _ \|  _ \| ____| | \ | | ____|_   _| ##
## | |  | | | | |_) |  _|   |  \| |  _|   | |   ##
## | |__| |_| |  _ <| |___ _| |\  | |___  | |   ##
##  \____\__\_\_| \_\_____(_)_| \_|_____| |_|   ##
##################################################
## Project: Elysium                             ##
## File: Elysium.ps1                            ##
## Version: 1.2.0                               ##
## Support: support@cqre.net                    ##
##################################################

<#
.SYNOPSIS
This is the main script for the Elysium tool for testing weak AD passwords.

.DESCRIPTION
Elysium.ps1 offers a menu to perform various actions:
1. Download/Update Known-Hashes Database (KHDB)
2. Test Weak AD Passwords
3. Extract and Send Current Hashes for KHDB Update
4. Uninstall the tool
5. Exit
#>

# Safer defaults
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Define the path to the settings file
$settingsFilePath = Join-Path -Path $PSScriptRoot -ChildPath "ElysiumSettings.txt"

# Check if the settings file exists
if (-Not (Test-Path $settingsFilePath)) {
    Write-Host "ElysiumSettings.txt does not exist. Please ensure your settings file is in the correct location."
    exit
} else {
    Write-Host "ElysiumSettings.txt found."
}

# Attempt to retrieve the passphrase from the environment variable
$passphrase = [System.Environment]::GetEnvironmentVariable("ELYSIUM_PASSPHRASE", [System.EnvironmentVariableTarget]::User)

if ([string]::IsNullOrEmpty($passphrase)) {
    Write-Host "No passphrase found in environment variables."
    $passphrase = Read-Host "Please enter your passphrase."
    # Here you could choose to set the environment variable or simply use the passphrase for the current session
    [System.Environment]::SetEnvironmentVariable("ELYSIUM_PASSPHRASE", $passphrase, [System.EnvironmentVariableTarget]::User)
    Write-Host "Passphrase stored as environment variable 'ELYSIUM_PASSPHRASE'."
} else {
    Write-Host "Passphrase found in environment variables."
}

# Continue with the rest of your script...

function Start-OrchestratorTranscript {
    param([string]$BasePath)
    try {
        $logsDir = Join-Path -Path $BasePath -ChildPath 'Reports/logs'
        if (-not (Test-Path $logsDir)) { New-Item -Path $logsDir -ItemType Directory -Force | Out-Null }
        $ts = Get-Date -Format 'yyyyMMdd-HHmmss'
        $logPath = Join-Path -Path $logsDir -ChildPath "orchestrator-$ts.log"
        Start-Transcript -Path $logPath -Force | Out-Null
    } catch {
        Write-Warning "Could not start transcript: $($_.Exception.Message)"
    }
}

function Stop-OrchestratorTranscript { try { Stop-Transcript | Out-Null } catch {} }

function Show-Menu {
    param (
        [string]$Title = 'Elysium Tool Main Menu'
    )
    Clear-Host
    Write-Host "================ $Title ================"
    Write-Host "1: Download/Update Known-Hashes Database (KHDB)"
    Write-Host "2: Test Weak AD Passwords"
    Write-Host "3: Extract and Send Current Hashes for KHDB Update"
    Write-Host "4: Uninstall"
    Write-Host "5: Exit"
}

Start-OrchestratorTranscript -BasePath $PSScriptRoot
try {
do {
    Show-Menu
    $userSelection = Read-Host "Please make a selection"
    switch ($userSelection) {
        '1' {
            Write-Host "Downloading KHDB..."
            & (Join-Path -Path $PSScriptRoot -ChildPath 'Update-KHDB.ps1')
        }
        '2' {
            Write-Host "Testing Weak AD Passwords..."
            & (Join-Path -Path $PSScriptRoot -ChildPath 'Test-WeakADPasswords.ps1')
        }
        '3' {
            Write-Host "Extracting and Sending Current Hashes..."
            & (Join-Path -Path $PSScriptRoot -ChildPath 'Extract-NTHashes.ps1')
        }
        '4' {
            Write-Host "Uninstalling..."
            & (Join-Path -Path $PSScriptRoot -ChildPath 'Uninstall.ps1')
        }
        '5' {
            Write-Host "Exiting..."
            # end loop; transcript will be stopped after the loop
            $userSelection = '5'
        }
        default {
            Write-Host "Invalid selection, please try again."
        }
    }
    pause
} while ($userSelection -ne '5')
} finally {
    Stop-OrchestratorTranscript
}
