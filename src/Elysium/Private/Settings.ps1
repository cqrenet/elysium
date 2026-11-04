# ---------------------------------------------------------------------------
# Settings loading
# ---------------------------------------------------------------------------

function Read-KeyValueSettingsFile {
    param([Parameter(Mandatory)][string]$Path)
    $result = @{}
    if (-not (Test-Path -LiteralPath $Path)) { return $result }
    foreach ($line in (Get-Content -LiteralPath $Path)) {
        if ($null -eq $line) { continue }
        $trimmed = $line.Trim()
        if (-not $trimmed) { continue }
        if ($trimmed.StartsWith('#')) { continue }
        $kv = $line -split '=', 2
        if ($kv.Count -ne 2) { continue }
        $key = $kv[0].Trim()
        $value = $kv[1].Trim()
        if (-not $key) { continue }
        if ($value.StartsWith("'") -and $value.EndsWith("'") -and $value.Length -ge 2) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        $result[$key] = $value
    }
    return $result
}

function Read-ElysiumSettings {
    param([Parameter(Mandatory)][string]$ScriptRoot)
    $settingsPath = Join-Path -Path $ScriptRoot -ChildPath 'ElysiumSettings.txt'
    if (-not (Test-Path -LiteralPath $settingsPath)) {
        throw "Settings file not found at $settingsPath"
    }
    return Read-KeyValueSettingsFile -Path $settingsPath
}

function Get-SettingsValue {
    param(
        [hashtable]$Settings,
        [string]$Key
    )
    if (-not $Settings) { return $null }
    if ($Settings.ContainsKey($Key)) { return $Settings[$Key] }
    return $null
}

function Get-BooleanSetting {
    param(
        [string]$Value,
        [bool]$Default = $false
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return $Default }
    $parsed = $Default
    if ([System.Boolean]::TryParse($Value, [ref]$parsed)) { return $parsed }
    return $Default
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

# Define the function to extract domain details from settings
function Get-DomainDetailsFromSettings {
    param (
        [hashtable]$Settings
    )

    $domainDetails = [ordered]@{}
    $counter = 1
    while ($true) {
        $nameKey = "Domain${counter}Name"
        $dcKey = "Domain${counter}DC"
        if ($Settings.ContainsKey($nameKey)) {
            $domainDetails["$counter"] = @{
                Name = $Settings[$nameKey]
                DC   = $Settings[$dcKey]
            }
            $counter++
        }
        else {
            break
        }
    }
    return $domainDetails
}

function Normalize-ReportPath([string]$p) {
    if ([string]::IsNullOrWhiteSpace($p)) { return (Join-Path -Path $InstallRoot -ChildPath 'Reports') }
    if ([System.IO.Path]::IsPathRooted($p)) { return $p }
    return (Join-Path -Path $InstallRoot -ChildPath $p)
}
