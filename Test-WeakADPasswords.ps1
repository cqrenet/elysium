##################################################
##   ____ ___  ____  _____   _   _ _____ _____  ##
##  / ___/ _ \|  _ \| ____| | \ | | ____|_   _| ##
## | |  | | | | |_) |  _|   |  \| |  _|   | |   ##
## | |__| |_| |  _ <| |___ _| |\  | |___  | |   ##
##  \____\__\_\_| \_\_____(_)_| \_|_____| |_|   ##
##          Move fast and fix things.           ##
##################################################
## Project: Elysium                             ##
## File: Test-WeakADPasswords.ps1               ##
## Support: support@cqre.net                    ##
##################################################

<#
.SYNOPSIS
Weak AD password finder component of Elysium tool.

.DESCRIPTION
This script will test the passwords of selected domain (defined in ElysiumSettings.txt) using DSInternals' Test-PasswordQuality cmdlet. It writes its output to a report file which is meant to be shared with the internal security team. The report now includes UPNs for each account mentioned.

Thin wrapper around the Test-ElysiumPasswordQuality cmdlet in src/Elysium, kept so existing
invocations and the menu keep working.
#>

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

[string]$commonHelper = Join-Path -Path $PSScriptRoot -ChildPath 'Elysium.Common.ps1'
if (-not (Test-Path -LiteralPath $commonHelper)) { throw "Common helper not found at $commonHelper" }
. $commonHelper
Restart-WithWindowsPowerShellIfAvailable -BoundParameters $PSBoundParameters -UnboundArguments $MyInvocation.UnboundArguments

Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath 'src/Elysium/Elysium.psd1') -Force
Test-ElysiumPasswordQuality
Write-Host "Script execution completed."
