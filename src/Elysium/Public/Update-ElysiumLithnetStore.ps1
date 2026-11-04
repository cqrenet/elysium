function Update-ElysiumLithnetStore {
    <#
    .SYNOPSIS
    Populates a Lithnet Password Protection store with compromised passwords and banned words.

    .DESCRIPTION
    Reads configuration from ElysiumSettings.txt (or a provided settings file), opens the Lithnet
    Password Protection store, optionally synchronizes with Have I Been Pwned, imports local NTLM
    hash lists, plaintext password lists, and banned-word files. With no hash list configured or
    passed, the KHDB that Update-ElysiumKhdb maintains is imported.
    #>
    [CmdletBinding()]
    param(
        [string]$SettingsPath,
        [string[]]$HashFiles,
        [string[]]$PlaintextFiles,
        [string[]]$BannedWordFiles,
        [switch]$SkipHibpSync
    )

    Start-ElysiumTranscript -BasePath $InstallRoot -Name 'update-lithnet'
    try {
        if (-not $SettingsPath) {
            $SettingsPath = Join-Path -Path $InstallRoot -ChildPath 'ElysiumSettings.txt'
        }
        if (-not (Test-Path -LiteralPath $SettingsPath)) { throw "Settings file not found at $SettingsPath" }
        $settings = Read-KeyValueSettingsFile -Path $SettingsPath

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
            $defaultKhdb = Get-KhdbPath $settings
            if (Test-Path -LiteralPath $defaultKhdb) {
                [void]$hashSourcePaths.Add((Resolve-Path -LiteralPath $defaultKhdb).Path)
            } else {
                throw "No hash files were provided via parameters or LithnetHashSources, and the KHDB was not found at '$defaultKhdb'."
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

            foreach ($hashFile in ($hashSourcePaths | Sort-Object)) {
                Write-Host ("Importing NTLM hash list '{0}'..." -f $hashFile)
                Import-CompromisedPasswordHashes -Filename $hashFile
            }

            foreach ($plainFile in ($plaintextSourcePaths | Sort-Object)) {
                Write-Host ("Importing plaintext password list '{0}'..." -f $plainFile)
                Import-CompromisedPasswords -Filename $plainFile
            }

            foreach ($bannedFile in ($bannedWordSourcePaths | Sort-Object)) {
                Write-Host ("Importing banned word list '{0}'..." -f $bannedFile)
                Import-BannedWords -Filename $bannedFile
            }

            Write-Host 'Lithnet store update completed successfully.'
        } finally {
            if ($storeOpened) {
                try { Close-Store } catch {}
            }
        }
    } finally {
        Stop-ElysiumTranscript
    }
}
