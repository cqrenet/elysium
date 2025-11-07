##################################################
##   ____ ___  ____  _____   _   _ _____ _____  ##
##  / ___/ _ \|  _ \| ____| | \ | | ____|_   _| ##
## | |  | | | | |_) |  _|   |  \| |  _|   | |   ##
## | |__| |_| |  _ <| |___ _| |\  | |___  | |   ##
##  \____\__\_\_| \_\_____(_)_| \_|_____| |_|   ##
##################################################
## Project: Elysium                             ##
## File: Update-LithnetStore.ps1                ##
## Version: 1.0.0                               ##
## Support: support@cqre.net                    ##
##################################################

<#
.SYNOPSIS
Populates a Lithnet Password Protection store with compromised passwords and banned words.

.DESCRIPTION
Reads configuration from ElysiumSettings.txt (or a provided settings file), opens the Lithnet
Password Protection store, optionally synchronizes with Have I Been Pwned, imports local NTLM
hash lists, plaintext password lists, and banned-word files.
#>

[CmdletBinding()]
param(
    [string]$SettingsPath,
    [string[]]$HashFiles,
    [string[]]$PlaintextFiles,
    [string[]]$BannedWordFiles,
    [switch]$SkipHibpSync
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
[string]$commonHelper = Join-Path -Path $PSScriptRoot -ChildPath 'Elysium.Common.ps1'
if (-not (Test-Path -LiteralPath $commonHelper)) { throw "Common helper not found at $commonHelper" }
. $commonHelper
Restart-WithPwshIfAvailable -BoundParameters $PSBoundParameters -UnboundArguments $MyInvocation.UnboundArguments

function Read-KeyValueSettings {
    param([string]$Path)
    $result = @{}
    if (-not (Test-Path -LiteralPath $Path)) { throw "Settings file not found at $Path" }
    Get-Content -LiteralPath $Path | ForEach-Object {
        $line = $_
        if (-not $line) { return }
        $trimmed = $line.Trim()
        if (-not $trimmed) { return }
        if ($trimmed.StartsWith('#')) { return }
        $kv = $line -split '=', 2
        if ($kv.Count -ne 2) { return }
        $key = $kv[0].Trim()
        $value = $kv[1].Trim()
        if (-not $key) { return }
        if ($value.StartsWith("'") -and $value.EndsWith("'") -and $value.Length -ge 2) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        $result[$key] = $value
    }
    return $result
}

function Get-BooleanSetting {
    param(
        [string]$Value,
        [bool]$Default = $false
    )
    if ([string]::IsNullOrWhiteSpace($Value)) { return $Default }
    try { return [System.Convert]::ToBoolean($Value) } catch { return $Default }
}

function Get-ListFromSetting {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return @() }
    return ($Value -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

function Resolve-ExistingPath {
    param([string]$PathValue, [string]$Description)
    if ([string]::IsNullOrWhiteSpace($PathValue)) { throw "$Description path was not provided." }
    if (-not (Test-Path -LiteralPath $PathValue)) {
        throw "$Description not found at '$PathValue'."
    }
    return (Resolve-Path -LiteralPath $PathValue).Path
}

if (-not $SettingsPath) {
    $SettingsPath = Join-Path -Path $PSScriptRoot -ChildPath 'ElysiumSettings.txt'
}
$settings = Read-KeyValueSettings -Path $SettingsPath

$storePathSetting = $settings['LithnetStorePath']
$storePath = Resolve-ExistingPath -PathValue $storePathSetting -Description 'Lithnet store'

$settingsHashSources = Get-ListFromSetting -Value $settings['LithnetHashSources']
$settingsPlainSources = Get-ListFromSetting -Value $settings['LithnetPlaintextSources']
$settingsBannedSources = Get-ListFromSetting -Value $settings['LithnetBannedWordSources']

$hashSourcePaths = New-Object System.Collections.Generic.HashSet[string] ([System.StringComparer]::OrdinalIgnoreCase)
foreach ($path in @($HashFiles) + $settingsHashSources) {
    if ([string]::IsNullOrWhiteSpace($path)) { continue }
    $resolved = Resolve-ExistingPath -PathValue $path -Description 'Hash list'
    [void]$hashSourcePaths.Add($resolved)
}
if ($hashSourcePaths.Count -eq 0) {
    $defaultKhdb = Join-Path -Path $PSScriptRoot -ChildPath 'khdb.txt'
    if (Test-Path -LiteralPath $defaultKhdb) {
        [void]$hashSourcePaths.Add((Resolve-Path -LiteralPath $defaultKhdb).Path)
    } else {
        throw 'No hash files were provided via parameters or LithnetHashSources, and khdb.txt was not found.'
    }
}

$plaintextSourcePaths = New-Object System.Collections.Generic.HashSet[string] ([System.StringComparer]::OrdinalIgnoreCase)
foreach ($path in @($PlaintextFiles) + $settingsPlainSources) {
    if ([string]::IsNullOrWhiteSpace($path)) { continue }
    $resolved = Resolve-ExistingPath -PathValue $path -Description 'Plaintext password list'
    [void]$plaintextSourcePaths.Add($resolved)
}

$bannedWordSourcePaths = New-Object System.Collections.Generic.HashSet[string] ([System.StringComparer]::OrdinalIgnoreCase)
foreach ($path in @($BannedWordFiles) + $settingsBannedSources) {
    if ([string]::IsNullOrWhiteSpace($path)) { continue }
    $resolved = Resolve-ExistingPath -PathValue $path -Description 'Banned word list'
    [void]$bannedWordSourcePaths.Add($resolved)
}

$syncHibp = Get-BooleanSetting -Value $settings['LithnetSyncHibp'] -Default:$false
if ($SkipHibpSync) { $syncHibp = $false }

Write-Host "Importing LithnetPasswordProtection module..."
try {
    Import-Module -Name LithnetPasswordProtection -ErrorAction Stop | Out-Null
} catch {
    throw "LithnetPasswordProtection module not found: $($_.Exception.Message). Install it from https://github.com/lithnet/password-protection."
}

Write-Host ("Opening Lithnet store at '{0}'..." -f $storePath)
Open-Store -Path $storePath
$storeOpened = $true
try {
    if ($syncHibp) {
        Write-Host 'Synchronizing compromised hashes from Have I Been Pwned (this can take a while)...'
        Sync-HashesFromHibp
    }

    foreach ($hashFile in ($hashSourcePaths.ToArray() | Sort-Object)) {
        Write-Host ("Importing NTLM hash list '{0}'..." -f $hashFile)
        Import-CompromisedPasswordHashes -Filename $hashFile
    }

    foreach ($plainFile in ($plaintextSourcePaths.ToArray() | Sort-Object)) {
        Write-Host ("Importing plaintext password list '{0}'..." -f $plainFile)
        Import-CompromisedPasswords -Filename $plainFile
    }

    foreach ($bannedFile in ($bannedWordSourcePaths.ToArray() | Sort-Object)) {
        Write-Host ("Importing banned word list '{0}'..." -f $bannedFile)
        Import-BannedWords -Filename $bannedFile
    }

    Write-Host 'Lithnet store update completed successfully.'
} finally {
    if ($storeOpened) {
        try { Close-Store } catch {}
    }
}
