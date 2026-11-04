##################################################
##   ____ ___  ____  _____   _   _ _____ _____  ##
##  / ___/ _ \|  _ \| ____| | \ | | ____|_   _| ##
## | |  | | | | |_) |  _|   |  \| |  _|   | |   ##
## | |__| |_| |  _ <| |___ _| |\  | |___  | |   ##
##  \____\__\_\_| \_\_____(_)_| \_|_____| |_|   ##
##################################################
## Project: Elysium                             ##
## File: Update-LithnetStore.ps1                ##
## Support: support@cqre.net                    ##
##################################################

<#
.SYNOPSIS
Populates a Lithnet Password Protection store with compromised passwords and banned words.

.DESCRIPTION
Reads configuration from ElysiumSettings.txt (or a provided settings file), opens the Lithnet
Password Protection store, optionally synchronizes with Have I Been Pwned, imports local NTLM
hash lists, plaintext password lists, and banned-word files.

Thin wrapper around the Update-ElysiumLithnetStore cmdlet in src/Elysium, kept so existing
invocations and the menu keep working.
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

Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath 'src/Elysium/Elysium.psd1') -Force
Update-ElysiumLithnetStore @PSBoundParameters
