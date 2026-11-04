##################################################
##   ____ ___  ____  _____   _   _ _____ _____  ##
##  / ___/ _ \|  _ \| ____| | \ | | ____|_   _| ##
## | |  | | | | |_) |  _|   |  \| |  _|   | |   ##
## | |__| |_| |  _ <| |___ _| |\  | |___  | |   ##
##  \____\__\_\_| \_\_____(_)_| \_|_____| |_|   ##
##################################################
## Project: Elysium                             ##
## File: Extract-NTHashes.ps1                   ##
## Support: support@cqre.net                    ##
##################################################

<#
.SYNOPSIS
Script for extracting NTLM hashes from live AD for further analysis.

.DESCRIPTION
This script will connect to selected domain (defined in ElysiumSettings.txt) using account with AD replication privileges and extract NTLM hashes from all active accounts. It will then compress and encrypt the resulting file, uploads it to designated Azure Storage account, checks for validity and then deletes everything. The hashes are extracted without usernames to minimise the sensitivity of the operation. Encryption is done with AES and passphrase that was defined in environment variable during first run.

Thin wrapper around the Send-ElysiumHashExport cmdlet in src/Elysium, kept so existing
invocations and the menu keep working.
#>

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

[string]$commonHelper = Join-Path -Path $PSScriptRoot -ChildPath 'Elysium.Common.ps1'
if (-not (Test-Path -LiteralPath $commonHelper)) { throw "Common helper not found at $commonHelper" }
. $commonHelper
Restart-WithWindowsPowerShellIfAvailable -BoundParameters $PSBoundParameters -UnboundArguments $MyInvocation.UnboundArguments

Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath 'src/Elysium/Elysium.psd1') -Force
Send-ElysiumHashExport
Write-Host "Script execution completed."
