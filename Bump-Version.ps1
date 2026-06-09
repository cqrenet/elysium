##################################################
##   ____ ___  ____  _____   _   _ _____ _____  ##
##  / ___/ _ \|  _ \| ____| | \ | | ____|_   _| ##
## | |  | | | | |_) |  _|   |  \| |  _|   | |   ##
## | |__| |_| |  _ <| |___ _| |\  | |___  | |   ##
##  \____\__\_\_| \_\_____(_)_| \_|_____| |_|   ##
##          Move fast and fix things.           ##
##################################################
## Project: Elysium                             ##
## File: Bump-Version.ps1                       ##
## Version: 2.2.5                               ##
## Support: support@cqre.net                    ##
##################################################

#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

<#
.SYNOPSIS
    Bumps the unified Elysium version across all project files.

.DESCRIPTION
    Updates the centralized $ElysiumVersion variable, ASCII headers in all
    operational scripts, the settings template, and runtime references
    (User-Agent, usage beacon, etc.). Optionally stubs a new CHANGELOG entry.

.PARAMETER NewVersion
    The new version string to apply (e.g. 2.2.2).

.PARAMETER SkipChangelog
    Do not print a CHANGELOG entry stub.

.EXAMPLE
    .\Bump-Version.ps1 -NewVersion 2.2.2
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$NewVersion,

    [switch]$SkipChangelog
)

$scriptRoot = $PSScriptRoot
if (-not $scriptRoot) { $scriptRoot = (Get-Location).Path }

# ---------------------------------------------------------------------------
# Validate input
# ---------------------------------------------------------------------------
if ($NewVersion -notmatch '^\d+\.\d+\.\d+$') {
    throw "Version must be in semantic format X.Y.Z (e.g. 2.2.2). Got: '$NewVersion'"
}

# ---------------------------------------------------------------------------
# Determine current version from Elysium.Common.ps1
# ---------------------------------------------------------------------------
$commonPath = Join-Path -Path $scriptRoot -ChildPath 'Elysium.Common.ps1'
if (-not (Test-Path -LiteralPath $commonPath)) {
    throw "Elysium.Common.ps1 not found at $commonPath"
}

$commonContent = Get-Content -LiteralPath $commonPath -Raw
$currentVersionMatch = [regex]::Match($commonContent, "\`$script:ElysiumVersion\s*=\s*'([^']+)'")
if (-not $currentVersionMatch.Success) {
    throw "Could not determine current version from Elysium.Common.ps1"
}
$oldVersion = $currentVersionMatch.Groups[1].Value

if ($oldVersion -eq $NewVersion) {
    Write-Warning "Current version is already $NewVersion. Nothing to do."
    return
}

Write-Host "Bumping Elysium from $oldVersion -> $NewVersion"

# ---------------------------------------------------------------------------
# Helper: replace in file
# ---------------------------------------------------------------------------
function Edit-FileVersion {
    param(
        [string]$Path,
        [string]$Old,
        [string]$New
    )
    $content = Get-Content -LiteralPath $Path -Raw
    $newContent = $content.Replace($Old, $New)
    if ($newContent -eq $content) {
        Write-Verbose "  No changes in $(Split-Path -Leaf $Path)"
    } else {
        Set-Content -LiteralPath $Path -Value $newContent -NoNewline -Encoding UTF8
        Write-Host "  Updated $(Split-Path -Leaf $Path)"
    }
}

# ---------------------------------------------------------------------------
# 1. Central version variable
# ---------------------------------------------------------------------------
Write-Host "`n[1/4] Updating centralized version variable..."
Edit-FileVersion -Path $commonPath -Old "`$script:ElysiumVersion = '$oldVersion'" -New "`$script:ElysiumVersion = '$NewVersion'"

# ---------------------------------------------------------------------------
# 2. ASCII headers in scripts and templates
# ---------------------------------------------------------------------------
Write-Host "`n[2/4] Updating script headers..."
$headerTargets = Get-ChildItem -Path $scriptRoot -File | Where-Object {
    $_.Extension -in @('.ps1', '.py') -or $_.Name -eq 'ElysiumSettings.txt.sample'
}
foreach ($file in $headerTargets) {
    $content = Get-Content -LiteralPath $file.FullName -Raw
    # The header pattern: ## Version: X.Y.Z                               ##
    $pattern = "## Version:\s+$([regex]::Escape($oldVersion))\s+##"
    $replacement = "## Version: $NewVersion                               ##"
    $newContent = [regex]::Replace($content, $pattern, $replacement)
    if ($newContent -ne $content) {
        Set-Content -LiteralPath $file.FullName -Value $newContent -NoNewline -Encoding UTF8
        Write-Host "  Updated $($file.Name)"
    }
}

# ---------------------------------------------------------------------------
# 3. Runtime references (safety net)
# ---------------------------------------------------------------------------
Write-Host "`n[3/4] Updating runtime version references..."
$runtimeTargets = Get-ChildItem -Path $scriptRoot -Filter '*.ps1' -File
foreach ($file in $runtimeTargets) {
    $content = Get-Content -LiteralPath $file.FullName -Raw
    $newContent = $content
    # User-Agent patterns: 'Elysium/2.2.1 (+...)' or "Elysium/2.2.1 (+...)"
    $newContent = [regex]::Replace($newContent,
        "Elysium/$([regex]::Escape($oldVersion))",
        "Elysium/$NewVersion")
    # Literal string assignments: version = '2.2.1'
    $newContent = [regex]::Replace($newContent,
        "version\s*=\s*'$([regex]::Escape($oldVersion))'",
        "version  = '$NewVersion'")
    if ($newContent -ne $content) {
        Set-Content -LiteralPath $file.FullName -Value $newContent -NoNewline -Encoding UTF8
        Write-Host "  Updated runtime refs in $($file.Name)"
    }
}

# ---------------------------------------------------------------------------
# 4. CHANGELOG stub
# ---------------------------------------------------------------------------
if (-not $SkipChangelog) {
    Write-Host "`n[4/4] CHANGELOG entry stub (copy-paste ready):"
    $today = (Get-Date).ToString('yyyy-MM-dd')
    $stub = @"

---

## [$NewVersion] — $today

### Changed
- (describe your change here)
"@
    Write-Host $stub
    Write-Host "`nAppend the above to CHANGELOG.md, then commit and tag."
}

Write-Host "`nDone. Review the changes with: git diff --stat"
