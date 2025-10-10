##################################################
##   ____ ___  ____  _____   _   _ _____ _____  ##
##  / ___/ _ \|  _ \| ____| | \ | | ____|_   _| ##
## | |  | | | | |_) |  _|   |  \| |  _|   | |   ##
## | |__| |_| |  _ <| |___ _| |\  | |___  | |   ##
##  \____\__\_\_| \_\_____(_)_| \_|_____| |_|   ##
##################################################
## Project: Elysium                             ##
## File: Update-KHDB.ps1                        ##
## Version: 1.1.0                               ##
## Support: support@cqre.net                    ##
##################################################

<#
.SYNOPSIS
Known hashes database update script for the Elysium AD password testing tool.

.DESCRIPTION
This script downloads khdb.txt.zip from the designated Azure Storage account, validates and decompresses it, and atomically updates the current version with backup and logging.
#>

# safer defaults
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# ensure TLS 1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# Resolve paths
$scriptRoot = $PSScriptRoot

function Start-UpdateTranscript {
    param(
        [string]$BasePath
    )
    try {
        $logsDir = Join-Path -Path $BasePath -ChildPath 'Reports/logs'
        if (-not (Test-Path $logsDir)) { New-Item -Path $logsDir -ItemType Directory -Force | Out-Null }
        $ts = Get-Date -Format 'yyyyMMdd-HHmmss'
        $logPath = Join-Path -Path $logsDir -ChildPath "update-khdb-$ts.log"
        Start-Transcript -Path $logPath -Force | Out-Null
    } catch {
        Write-Warning "Could not start transcript: $($_.Exception.Message)"
    }
}

function Stop-UpdateTranscript {
    try { Stop-Transcript | Out-Null } catch {}
}

function Read-ElysiumSettings {
    $settings = @{}
    $settingsPath = Join-Path -Path $scriptRoot -ChildPath 'ElysiumSettings.txt'
    if (-not (Test-Path $settingsPath)) { throw "Settings file not found at $settingsPath" }
    Get-Content $settingsPath | ForEach-Object {
        if ($_ -and -not $_.Trim().StartsWith('#')) {
            $kv = $_ -split '=', 2
            if ($kv.Count -eq 2) { $settings[$kv[0].Trim()] = $kv[1].Trim().Trim("'") }
        }
    }
    return $settings
}

function Get-InstallationPath([hashtable]$settings) {
    $p = $settings['InstallationPath']
    if ([string]::IsNullOrWhiteSpace($p)) { return $scriptRoot }
    if ([System.IO.Path]::IsPathRooted($p)) { return $p }
    return (Join-Path -Path $scriptRoot -ChildPath $p)
}

function New-HttpClient {
    Add-Type -AssemblyName System.Net.Http
    $client = [System.Net.Http.HttpClient]::new()
    $client.Timeout = [TimeSpan]::FromSeconds(600)
    $client.DefaultRequestHeaders.UserAgent.ParseAdd('Elysium/1.1 (+Update-KHDB)')
    return $client
}

function Build-BlobUri([string]$account, [string]$container, [string]$sas) {
    if ([string]::IsNullOrWhiteSpace($account)) { throw 'storageAccountName is missing or empty.' }
    if ([string]::IsNullOrWhiteSpace($container)) { throw 'containerName is missing or empty.' }
    if ([string]::IsNullOrWhiteSpace($sas)) { throw 'sasToken is missing or empty.' }
    $sas = $sas.Trim()
    if (-not $sas.StartsWith('?')) { $sas = '?' + $sas }
    $ub = [System.UriBuilder]::new("https://$account.blob.core.windows.net/$container/khdb.txt.zip")
    $ub.Query = $sas.TrimStart('?')
    return $ub.Uri.AbsoluteUri
}

function Invoke-DownloadWithRetry([System.Net.Http.HttpClient]$client, [string]$uri, [string]$targetPath) {
    $retries = 5
    $delay = 2
    for ($i = 0; $i -lt $retries; $i++) {
        try {
            $resp = $client.GetAsync($uri, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).Result
            if (-not $resp.IsSuccessStatusCode) {
                $code = [int]$resp.StatusCode
                if (($code -ge 500 -and $code -lt 600) -or $code -eq 429 -or $code -eq 408) { throw "Transient HTTP error $code" }
                throw "HTTP error $code"
            }
            $totalBytes = $resp.Content.Headers.ContentLength
            $stream = $resp.Content.ReadAsStreamAsync().Result
            $fs = [System.IO.File]::Create($targetPath)
            try {
                $buffer = New-Object byte[] 8192
                $totalRead = 0
                while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    $fs.Write($buffer, 0, $read)
                    $totalRead += $read
                    if ($totalBytes) {
                        $pct = ($totalRead * 100.0) / $totalBytes
                        Write-Progress -Activity "Downloading khdb.txt.zip" -Status ("{0:N2}% Complete" -f $pct) -PercentComplete $pct
                    } else {
                        Write-Progress -Activity "Downloading khdb.txt.zip" -Status ("Downloaded {0:N0} bytes" -f $totalRead) -PercentComplete 0
                    }
                }
            } finally {
                $fs.Close(); $stream.Close()
            }
            return
        } catch {
            if ($i -lt ($retries - 1)) {
                Write-Warning "Download failed (attempt $($i+1)/$retries): $($_.Exception.Message). Retrying in ${delay}s..."
                Start-Sleep -Seconds $delay
                $delay = [Math]::Min($delay * 2, 30)
            } else {
                throw
            }
        }
    }
}

function Validate-KHDBFile([string]$path) {
    if (-not (Test-Path $path)) { throw "Validation failed: $path not found" }
    $lines = Get-Content -Path $path -Encoding UTF8
    if (-not $lines -or $lines.Count -eq 0) { throw 'Validation failed: file is empty.' }
    $regex = '^[0-9A-Fa-f]{32}$'
    $invalid = $lines | Where-Object { $_ -notmatch $regex }
    if ($invalid.Count -gt 0) {
        throw ("Validation failed: {0} invalid lines detected." -f $invalid.Count)
    }
    # Deduplicate and normalize line endings
    $unique = $lines | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Sort-Object -Unique
    Set-Content -Path $path -Value $unique -Encoding ASCII
}

function Update-KHDB {
    Start-UpdateTranscript -BasePath $scriptRoot
    try {
        $settings = Read-ElysiumSettings
        $installPath = Get-InstallationPath $settings
        if (-not (Test-Path $installPath)) { New-Item -Path $installPath -ItemType Directory -Force | Out-Null }

        $storageAccountName = $settings['storageAccountName']
        $containerName = $settings['containerName']
        $sasToken = $settings['sasToken']
        $uri = Build-BlobUri -account $storageAccountName -container $containerName -sas $sasToken

        $client = New-HttpClient
        $tmpDir = New-Item -ItemType Directory -Path ([System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "elysium-khdb-" + [System.Guid]::NewGuid())) -Force
        $zipPath = Join-Path -Path $tmpDir.FullName -ChildPath 'khdb.txt.zip'
        $extractDir = Join-Path -Path $tmpDir.FullName -ChildPath 'extract'
        New-Item -ItemType Directory -Path $extractDir -Force | Out-Null

        Write-Host "Downloading KHDB from Azure Blob Storage..."
        Invoke-DownloadWithRetry -client $client -uri $uri -targetPath $zipPath
        Write-Host "Download completed. Extracting archive..."

        Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force

        $extractedKHDB = Get-ChildItem -Path $extractDir -Recurse -Filter 'khdb.txt' | Select-Object -First 1
        if (-not $extractedKHDB) { throw 'Extracted archive does not contain khdb.txt.' }

        # Validate content
        Validate-KHDBFile -path $extractedKHDB.FullName

        # Compute target path and backup
        $targetKHDB = Join-Path -Path $installPath -ChildPath 'khdb.txt'
        if (Test-Path $targetKHDB) {
            $ts = Get-Date -Format 'yyyyMMdd-HHmmss'
            $backupPath = Join-Path -Path $installPath -ChildPath ("khdb.txt.bak-$ts")
            Copy-Item -Path $targetKHDB -Destination $backupPath -Force
            Write-Host "Existing KHDB backed up to $backupPath"
        }

        # Atomic-ish replace: move validated file into place
        Move-Item -Path $extractedKHDB.FullName -Destination $targetKHDB -Force
        Write-Host "KHDB updated at $targetKHDB"
        Write-Host "KHDB update completed successfully."
    } catch {
        Write-Error ("KHDB update failed: {0}" -f $_.Exception.Message)
        throw
    } finally {
        try { if ($tmpDir -and (Test-Path $tmpDir.FullName)) { Remove-Item -Path $tmpDir.FullName -Recurse -Force } } catch {}
        Stop-UpdateTranscript
    }
}

# Execute the update function
Update-KHDB
Write-Host "Script execution completed."
