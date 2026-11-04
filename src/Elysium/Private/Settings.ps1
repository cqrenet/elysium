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
