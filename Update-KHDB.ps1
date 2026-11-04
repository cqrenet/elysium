##################################################
##   ____ ___  ____  _____   _   _ _____ _____  ##
##  / ___/ _ \|  _ \| ____| | \ | | ____|_   _| ##
## | |  | | | | |_) |  _|   |  \| |  _|   | |   ##
## | |__| |_| |  _ <| |___ _| |\  | |___  | |   ##
##  \____\__\_\_| \_\_____(_)_| \_|_____| |_|   ##
##################################################
## Project: Elysium                             ##
## File: Update-KHDB.ps1                        ##
## Support: support@cqre.net                    ##
##################################################

<#
.SYNOPSIS
Known-hashes database updater for the Elysium AD password testing tool.

.DESCRIPTION
Downloads a sharded KHDB manifest, performs incremental shard updates, validates
checksums, and atomically refreshes the merged khdb.txt for downstream scripts.
Supports Azure Blob Storage (via SAS) and S3-compatible endpoints (SigV4).

Thin wrapper around the Update-ElysiumKhdb cmdlet in src/Elysium, kept so existing
invocations and the menu keep working.

.PARAMETER MaxParallelTransfers
Concurrent shard downloads on PowerShell 7+ (default 5).
#>

[CmdletBinding()]
param(
    [ValidateRange(1, 64)]
    [int]$MaxParallelTransfers = 5
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

[string]$commonHelper = Join-Path -Path $PSScriptRoot -ChildPath 'Elysium.Common.ps1'
if (-not (Test-Path -LiteralPath $commonHelper)) { throw "Common helper not found at $commonHelper" }
. $commonHelper
Restart-WithPwshIfAvailable -BoundParameters $PSBoundParameters -UnboundArguments $MyInvocation.UnboundArguments

Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath 'src/Elysium/Elysium.psd1') -Force
Update-ElysiumKhdb @PSBoundParameters
Write-Host "Script execution completed."
