##################################################
##   ____ ___  ____  _____   _   _ _____ _____  ##
##  / ___/ _ \|  _ \| ____| | \ | | ____|_   _| ##
## | |  | | | | |_) |  _|   |  \| |  _|   | |   ##
## | |__| |_| |  _ <| |___ _| |\  | |___  | |   ##
##  \____\__\_\_| \_\_____(_)_| \_|_____| |_|   ##
##################################################
## Project: Elysium                             ##
## File: Elysium.ps1                            ##
## Version: 2.4.4                               ##
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
5. Update Lithnet Password Protection store
6. Exit
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

function Invoke-WindowsPowerShellScript {
    param([string]$ScriptPath)
    $powershellCmd = Get-Command -Name 'powershell.exe' -ErrorAction SilentlyContinue
    if (-not $powershellCmd) {
        throw "Windows PowerShell (powershell.exe) was not found. Install it or run the script from a Desktop edition session."
    }
    $args = @('-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $ScriptPath)
    & $powershellCmd.Path @args
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw ("Windows PowerShell script '{0}' exited with code {1}." -f $ScriptPath, $exitCode)
    }
}

function Show-Menu {
    param (
        [string]$Title = 'Elysium Tool Main Menu'
    )
    Clear-Host
    Write-Host "================ $Title ================"
    Write-Host "1: Download/Update Known-Hashes Database (KHDB)"
    Write-Host "2: Test Weak AD Passwords"
    Write-Host "3: Extract and Send Current Hashes for KHDB Update"
    Write-Host "4: Update Lithnet Password Protection Store"
    Write-Host "5: Uninstall"
    Write-Host "6: Exit"
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
            $testScript = Join-Path -Path $PSScriptRoot -ChildPath 'Test-WeakADPasswords.ps1'
            if ($PSVersionTable.PSEdition -eq 'Desktop') {
                & $testScript
            } else {
                Invoke-WindowsPowerShellScript -ScriptPath $testScript
            }
        }
        '3' {
            Write-Host "Extracting and Sending Current Hashes..."
            $extractScript = Join-Path -Path $PSScriptRoot -ChildPath 'Extract-NTHashes.ps1'
            if ($PSVersionTable.PSEdition -eq 'Desktop') {
                & $extractScript
            } else {
                Invoke-WindowsPowerShellScript -ScriptPath $extractScript
            }
        }
        '4' {
            Write-Host "Updating Lithnet Password Protection store..."
            & (Join-Path -Path $PSScriptRoot -ChildPath 'Update-LithnetStore.ps1')
        }
        '5' {
            Write-Host "Uninstalling..."
            & (Join-Path -Path $PSScriptRoot -ChildPath 'Uninstall.ps1')
        }
        '6' {
            Write-Host "Exiting..."
            # end loop; transcript will be stopped after the loop
            $userSelection = '6'
        }
        default {
            Write-Host "Invalid selection, please try again."
        }
    }
    pause
} while ($userSelection -ne '6')
} finally {
    Stop-OrchestratorTranscript
}
