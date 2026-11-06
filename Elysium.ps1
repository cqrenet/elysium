##################################################
##   ____ ___  ____  _____   _   _ _____ _____  ##
##  / ___/ _ \|  _ \| ____| | \ | | ____|_   _| ##
## | |  | | | | |_) |  _|   |  \| |  _|   | |   ##
## | |__| |_| |  _ <| |___ _| |\  | |___  | |   ##
##  \____\__\_\_| \_\_____(_)_| \_|_____| |_|   ##
##################################################
## Project: Elysium                             ##
## File: Elysium.ps1                            ##
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
4. Update Lithnet Password Protection store
5. Uninstall the tool
6. Exit
#>

# Safer defaults
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
# Pure keypress logic for the arrow-key menu below; kept in the module's Private/ so Pester can test
# it without a real console.
. (Join-Path -Path $PSScriptRoot -ChildPath 'src/Elysium/Private/Menu.ps1')
# Define the path to the settings file
$settingsFilePath = Join-Path -Path $PSScriptRoot -ChildPath "ElysiumSettings.txt"

# Check if the settings file exists
if (-Not (Test-Path $settingsFilePath)) {
    Write-Host "ElysiumSettings.txt does not exist. Please ensure your settings file is in the correct location."
    exit
} else {
    Write-Host "ElysiumSettings.txt found."
}

# The passphrase is persisted DPAPI-protected (current user + machine) via ConvertFrom-SecureString,
# never in plaintext, so it's only prompted for once per user/machine and never echoed to the console.
$storedPassphrase = [System.Environment]::GetEnvironmentVariable("ELYSIUM_PASSPHRASE", [System.EnvironmentVariableTarget]::User)

$havePassphrase = $false
if (-not [string]::IsNullOrEmpty($storedPassphrase)) {
    try {
        [void](ConvertTo-SecureString -String $storedPassphrase -ErrorAction Stop)
        $havePassphrase = $true
        Write-Host "Passphrase found in environment variables."
    } catch {
        Write-Warning "Stored passphrase is not in the expected protected format (leftover from an older Elysium version?). Re-enter it."
    }
}

if (-not $havePassphrase) {
    Write-Host "No passphrase found in environment variables."
    $securePassphrase = Read-Host "Please enter your passphrase" -AsSecureString
    [System.Environment]::SetEnvironmentVariable("ELYSIUM_PASSPHRASE", (ConvertFrom-SecureString -SecureString $securePassphrase), [System.EnvironmentVariableTarget]::User)
    Write-Host "Passphrase stored (DPAPI-protected) as environment variable 'ELYSIUM_PASSPHRASE'."
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

$script:MenuItems = @(
    'Download/Update Known-Hashes Database (KHDB)'
    'Test Weak AD Passwords'
    'Extract and Send Current Hashes for KHDB Update'
    'Update Lithnet Password Protection Store'
    'Uninstall'
    'Exit'
)

function Show-Menu {
    <#
    .SYNOPSIS
    Draws the main menu and returns the chosen 1-based item, or $null if the operator backed out.

    .DESCRIPTION
    Arrow keys plus Enter, or a direct number key, drive the selection (logic in Resolve-ElysiumMenuKeyPress);
    Escape or Q backs out. Falls back to the plain numbered Read-Host prompt when input is redirected
    or the host has no real console (CI, some IDE terminals) - [Console]::ReadKey throws there.
    #>
    param (
        [string]$Title = 'Elysium Tool Main Menu'
    )

    $useFallback = [System.Console]::IsInputRedirected
    if (-not $useFallback) {
        try { [void]$Host.UI.RawUI.CursorPosition } catch { $useFallback = $true }
    }

    if ($useFallback) {
        while ($true) {
            Clear-Host
            Write-Host "================ $Title ================"
            for ($i = 0; $i -lt $script:MenuItems.Count; $i++) { Write-Host ("{0}: {1}" -f ($i + 1), $script:MenuItems[$i]) }
            $choice = Read-Host "Please make a selection"
            if ($choice -match '^[1-9]$' -and [int]$choice -le $script:MenuItems.Count) { return [int]$choice }
            if ($choice -match '^(?i:q)$') { return $null }
            Write-Host "Invalid selection, please try again."
        }
    }

    $index = 0
    $originalCursorVisible = [System.Console]::CursorVisible
    try {
        [System.Console]::CursorVisible = $false
        while ($true) {
            Clear-Host
            Write-Host "================ $Title ================"
            Write-Host "(Up/Down + Enter, or a number. Esc/Q to exit.)"
            for ($i = 0; $i -lt $script:MenuItems.Count; $i++) {
                $line = "{0}: {1}" -f ($i + 1), $script:MenuItems[$i]
                if ($i -eq $index) { Write-Host $line -BackgroundColor DarkCyan -ForegroundColor Black }
                else { Write-Host $line }
            }
            $keyInfo = [System.Console]::ReadKey($true)
            if ($keyInfo.Key -eq [System.ConsoleKey]::Q) { return $null }
            $step = Resolve-ElysiumMenuKeyPress -CurrentIndex $index -ItemCount $script:MenuItems.Count -Key $keyInfo.Key
            if ($step.Cancelled) { return $null }
            $index = $step.Index
            if ($step.Committed) { return $index + 1 }
        }
    } finally {
        [System.Console]::CursorVisible = $originalCursorVisible
    }
}

Start-OrchestratorTranscript -BasePath $PSScriptRoot
try {
do {
    $picked = Show-Menu
    $userSelection = if ($null -eq $picked) { '6' } else { "$picked" }
    try {
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
    } catch {
        Write-Error ("An error occurred while running the selected option: {0}" -f $_.Exception.Message)
    }
    pause
} while ($userSelection -ne '6')
} finally {
    Stop-OrchestratorTranscript
}
