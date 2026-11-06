function Update-ElysiumKhdb {
    <#
    .SYNOPSIS
    Downloads the sharded KHDB incrementally and rebuilds the merged khdb.txt.

    .DESCRIPTION
    Fetches the manifest from the configured storage (Azure Blob via SAS, or S3-compatible via
    SigV4), downloads only shards whose checksum changed, removes shards no longer listed, and
    replaces the merged KHDB file. The previous file is kept as khdb.txt.bak-<time>; KhdbBackupCount (default 1,
    0 = none) sets how many backups stay.

    .PARAMETER MaxParallelTransfers
    Shards downloaded concurrently (each in its own runspace), on Windows PowerShell 5.1 and 7 alike.
    #>
    [CmdletBinding()]
    param(
        [ValidateRange(1, 64)]
        [int]$MaxParallelTransfers = 5
    )
    Start-ElysiumTranscript -BasePath $InstallRoot -Name 'update-khdb'
    try {
        $settings = Read-ElysiumSettings -ScriptRoot $InstallRoot
        $installPath = Get-InstallationPath $settings
        Ensure-Directory $installPath

        $storage = Get-StorageConfig $settings

        $manifestBlobPath = $settings['KhdbManifestPath']
        if ([string]::IsNullOrWhiteSpace($manifestBlobPath)) { $manifestBlobPath = 'khdb/manifest.json' }

        $remoteShardPrefix = $settings['KhdbShardPrefix']
        if ([string]::IsNullOrWhiteSpace($remoteShardPrefix)) { $remoteShardPrefix = 'khdb/shards' }

        $localShardDirName = $settings['KhdbLocalShardDir']
        if ([string]::IsNullOrWhiteSpace($localShardDirName)) { $localShardDirName = 'khdb-shards' }

        $localShardRoot = Join-Path -Path $installPath -ChildPath $localShardDirName
        Ensure-Directory $localShardRoot

        $localManifestPath = Join-Path -Path $installPath -ChildPath 'khdb-manifest.json'
        $tmpDir = New-Item -ItemType Directory -Path ([System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "elysium-khdb-" + [System.Guid]::NewGuid())) -Force
        $manifestTempPath = Join-Path -Path $tmpDir.FullName -ChildPath 'manifest.json'
        $downloadTempRoot = Join-Path -Path $tmpDir.FullName -ChildPath 'shards'
        Ensure-Directory $downloadTempRoot

        Write-Host "Fetching manifest ($manifestBlobPath) from $($storage.Provider) storage..."
        Invoke-StorageDownload -Storage $storage -Key $manifestBlobPath -TargetPath $manifestTempPath

        $manifest = Load-Manifest -Path $manifestTempPath
        Validate-Manifest -Manifest $manifest
        if ($manifest.shardPrefix) {
            $remoteShardPrefix = [string]$manifest.shardPrefix
            Write-Verbose "Using shard prefix from manifest: $remoteShardPrefix"
        }

        $remoteShardPrefix = $remoteShardPrefix.Replace('\', '/')

        Write-Host ("Manifest downloaded. Found {0} shard(s)." -f $manifest.shards.Count)
        if ($manifest.version) {
            Write-Host ("Remote version: {0}" -f $manifest.version)
        }

        $localManifest = $null
        if (Test-Path -LiteralPath $localManifestPath) {
            try {
                $localManifest = Load-Manifest -Path $localManifestPath
            } catch {
                Write-Warning ("Failed to parse existing manifest. Full refresh will occur: {0}" -f $_.Exception.Message)
            }
        }

        $localManifestMap = @{}
        if ($localManifest -and $localManifest.shards) {
            foreach ($entry in $localManifest.shards) {
                if ($entry.name) { $localManifestMap[$entry.name] = $entry }
            }
        }

        $downloadQueue = [System.Collections.ArrayList]::new()
        $remoteNameSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($entry in $manifest.shards) {
            $name = [string]$entry.name
            [void]$remoteNameSet.Add($name)
            $expectedHash = ([string]$entry.sha256).ToLowerInvariant()
            $expectedSize = 0L
            if (-not [long]::TryParse([string]$entry.size, [ref]$expectedSize)) {
                throw "Cannot parse size for shard '$name'."
            }

            $localPath = Join-Path -Path $localShardRoot -ChildPath $name
            $needsDownload = $true

            if (Test-Path -LiteralPath $localPath) {
                $localInfo = Get-Item -LiteralPath $localPath
                if ($localInfo.Length -eq $expectedSize) {
                    $localManifestEntry = $null
                    if ($localManifestMap.ContainsKey($name)) {
                        $localManifestEntry = $localManifestMap[$name]
                    }
                    if ($localManifestEntry -and ([string]$localManifestEntry.sha256).ToLowerInvariant() -eq $expectedHash) {
                        $needsDownload = $false
                    } else {
                        $localHash = Get-FileSha256Lower -Path $localPath
                        if ($localHash -eq $expectedHash) { $needsDownload = $false }
                    }
                }
            }

            if ($needsDownload) {
                [void]$downloadQueue.Add([pscustomobject]@{
                    Name   = $name
                    Sha256 = $expectedHash
                    Size   = $expectedSize
                })
            }
        }

        if ($downloadQueue.Count -gt 0) {
            Write-Host ("{0} shard(s) require download or refresh; up to {1} concurrent transfer(s)." -f $downloadQueue.Count, $MaxParallelTransfers)
            $shardDownloads = foreach ($entry in $downloadQueue) {
                @{ Storage = $storage; RemotePrefix = $remoteShardPrefix; Name = $entry.Name; Sha256 = $entry.Sha256; Size = $entry.Size; StagingRoot = $downloadTempRoot; ShardRoot = $localShardRoot }
            }
            Invoke-InModuleRunspace -FunctionName 'Receive-KhdbShard' -ParameterSets $shardDownloads -ThrottleLimit $MaxParallelTransfers -Activity 'Downloading KHDB shards'
        } else {
            Write-Host 'All shards already up to date; verifying manifest and combined file.'
        }

        $existingShards = @()
        if (Test-Path -LiteralPath $localShardRoot) {
            $existingShards = Get-ChildItem -LiteralPath $localShardRoot -File -Recurse
        }

        $removed = 0
        foreach ($file in $existingShards) {
            $relative = Get-RelativePath -BasePath $localShardRoot -FullPath $file.FullName
            if (-not $remoteNameSet.Contains($relative)) {
                Remove-Item -LiteralPath $file.FullName -Force
                $removed++
            }
        }

        if ($removed -gt 0) {
            Write-Host ("Removed {0} stale shard(s)." -f $removed)
            Remove-EmptyDirectories -Root $localShardRoot
        }

        Copy-Item -LiteralPath $manifestTempPath -Destination $localManifestPath -Force
        Write-Host ("Manifest saved locally to {0}" -f $localManifestPath)

        $backupRetentionCount = 1
        $backupSetting = $settings['KhdbBackupCount']
        if (-not [string]::IsNullOrWhiteSpace($backupSetting) -and -not ([int]::TryParse($backupSetting, [ref]$backupRetentionCount) -and $backupRetentionCount -ge 0)) {
            throw "KhdbBackupCount must be a whole number of 0 or more (got '$backupSetting')."
        }

        $khdbName = if ([string]::IsNullOrWhiteSpace($settings['WeakPasswordsDatabase'])) { 'khdb.txt' } else { $settings['WeakPasswordsDatabase'] }
        $combinedTarget = Join-Path -Path $installPath -ChildPath $khdbName
        $combinedTemp = Join-Path -Path $tmpDir.FullName -ChildPath 'khdb-combined.txt'

        # Rebuilding the merged file is the slow step, so skip it when this exact manifest was already built
        # into place and nothing was downloaded or removed. The marker records the built file's own size
        # alongside the manifest hash: khdb.txt is tracked in git (unlike the shard cache and this marker),
        # so a `git pull`/`checkout` can silently replace a real build with the small repo-tracked sample
        # while leaving the marker and shard cache untouched - size alone catches that case cheaply. The
        # marker is written only after a successful build, so a failed run never leaves a skip-worthy state.
        $buildMarkerPath = Join-Path -Path $installPath -ChildPath 'khdb-build.sha256'
        $manifestHash = Get-FileSha256Lower -Path $manifestTempPath
        $lastBuildHash = $null
        $lastBuildSize = $null
        if (Test-Path -LiteralPath $buildMarkerPath) {
            $markerParts = (Get-Content -LiteralPath $buildMarkerPath -Raw).Trim() -split '\|', 2
            $lastBuildHash = $markerParts[0]
            if ($markerParts.Count -gt 1) { $lastBuildSize = $markerParts[1] }
        }
        $currentSize = if (Test-Path -LiteralPath $combinedTarget) { (Get-Item -LiteralPath $combinedTarget).Length } else { $null }

        if ($downloadQueue.Count -eq 0 -and $removed -eq 0 -and $lastBuildHash -eq $manifestHash -and $null -ne $currentSize -and "$currentSize" -eq $lastBuildSize) {
            Write-Host 'Manifest and shards unchanged since the last build; keeping the existing KHDB file.'
        } else {
            Write-Host "Rebuilding combined KHDB file..."
            Merge-ShardsToFile -Manifest $manifest -ShardsRoot $localShardRoot -TargetPath $combinedTemp
            Validate-KHDBFile -Path $combinedTemp

            $backupPath = $null
            if (Test-Path -LiteralPath $combinedTarget) {
                if ($backupRetentionCount -gt 0) {
                    # A move is instant on the same volume; copying a full-size KHDB took minutes.
                    $backupPath = Join-Path -Path $installPath -ChildPath ("$khdbName.bak-" + (Get-Date -Format 'yyyyMMdd-HHmmss'))
                    Move-Item -LiteralPath $combinedTarget -Destination $backupPath -Force
                    Write-Host ("Existing KHDB backed up to {0}" -f $backupPath)
                } else {
                    Remove-Item -LiteralPath $combinedTarget -Force
                }
            }

            try {
                Move-Item -LiteralPath $combinedTemp -Destination $combinedTarget -Force
            } catch {
                if ($backupPath) { Move-Item -LiteralPath $backupPath -Destination $combinedTarget -Force }
                throw
            }

            # Each run adds one full-size backup; keep only the newest few so a recurring scheduled job
            # doesn't silently fill the disk.
            $staleBackups = Get-ChildItem -LiteralPath $installPath -Filter "$khdbName.bak-*" -File -ErrorAction SilentlyContinue |
                Sort-Object Name -Descending | Select-Object -Skip $backupRetentionCount
            foreach ($stale in $staleBackups) {
                try { Remove-Item -LiteralPath $stale.FullName -Force } catch { Write-Warning "Could not remove old backup '$($stale.FullName)': $($_.Exception.Message)" }
            }
            $builtSize = (Get-Item -LiteralPath $combinedTarget).Length
            [System.IO.File]::WriteAllText($buildMarkerPath, "$manifestHash|$builtSize", [System.Text.UTF8Encoding]::new($false))
            Write-Host ("KHDB merged file refreshed at {0}" -f $combinedTarget)
        }
        Write-Host "KHDB update completed successfully."
    } catch {
        Write-Error ("KHDB update failed: {0}" -f $_.Exception.Message)
        throw
    } finally {
        try { if ($tmpDir -and (Test-Path $tmpDir.FullName)) { Remove-Item -Path $tmpDir.FullName -Recurse -Force } } catch {}
        Stop-ElysiumTranscript
    }
}
