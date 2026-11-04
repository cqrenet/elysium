function Update-ElysiumKhdb {
    <#
    .SYNOPSIS
    Downloads the sharded KHDB incrementally and rebuilds the merged khdb.txt.

    .DESCRIPTION
    Fetches the manifest from the configured storage (Azure Blob via SAS, or S3-compatible via
    SigV4), downloads only shards whose checksum changed, removes shards no longer listed, and
    atomically replaces the merged KHDB file (keeping the 5 most recent backups).

    .PARAMETER MaxParallelTransfers
    Concurrent shard downloads on PowerShell 7+. Windows PowerShell 5.1 always downloads serially.
    #>
    [CmdletBinding()]
    param(
        [ValidateRange(1, 64)]
        [int]$MaxParallelTransfers = 5
    )
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
    Start-ElysiumTranscript -BasePath $InstallRoot -Name 'update-khdb'
    try {
        $settings = Read-ElysiumSettings -ScriptRoot $InstallRoot
        $installPath = Get-InstallationPath $settings
        Ensure-Directory $installPath

        $psSupportsParallel = ($PSVersionTable.PSVersion.Major -ge 7)
        $effectiveParallelTransfers = if ($MaxParallelTransfers -lt 1) { 1 } else { [int]$MaxParallelTransfers }
        $parallelDownloadsEnabled = $psSupportsParallel -and $effectiveParallelTransfers -gt 1
        if (-not $psSupportsParallel -and $effectiveParallelTransfers -gt 1) {
            Write-Verbose "Parallel transfers requested but PowerShell $($PSVersionTable.PSVersion) does not support ForEach-Object -Parallel; using serial downloads."
        }
        $parallelAzureDownloadHelpers = $null
        $parallelAzureDownloadHelperList = @()
        $parallelS3DownloadHelpers = $null
        $parallelS3DownloadHelperList = @()
        if ($parallelDownloadsEnabled) {
            $parallelAzureDownloadHelpers = @{
                'Build-BlobUri'           = Get-FunctionDefinitionText 'Build-BlobUri'
                'Invoke-DownloadWithRetry' = Get-FunctionDefinitionText 'Invoke-DownloadWithRetry'
                'New-HttpClient'          = Get-FunctionDefinitionText 'New-HttpClient'
                'Get-FileSha256Lower'     = Get-FunctionDefinitionText 'Get-FileSha256Lower'
            }
            $parallelAzureDownloadHelperList = $parallelAzureDownloadHelpers.GetEnumerator() | ForEach-Object {
                [pscustomobject]@{ Name = $_.Key; Definition = $_.Value }
            }
            $parallelS3DownloadHelpers = @{}
            @(
                'Get-Bytes',
                'Get-HashHex',
                'HmacSha256',
                'ToHex',
                'GetSignatureKey',
                'UriEncode',
                'BuildCanonicalPath',
                'BuildAuthHeaders',
                'BuildS3Uri',
                'Invoke-S3HttpDownloadWithRetry',
                'Get-FileSha256Lower'
            ) | ForEach-Object {
                $parallelS3DownloadHelpers[$_] = Get-FunctionDefinitionText $_
            }
            $parallelS3DownloadHelperList = $parallelS3DownloadHelpers.GetEnumerator() | ForEach-Object {
                [pscustomobject]@{ Name = $_.Key; Definition = $_.Value }
            }
        }

        $storageProvider = $settings['StorageProvider']
        if ([string]::IsNullOrWhiteSpace($storageProvider)) { $storageProvider = 'Azure' }

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

        Write-Host "Fetching manifest ($manifestBlobPath) from $storageProvider storage..."

        $s3Bucket = $null
        $s3EndpointUrl = $null
        $s3Region = $null
        $s3AK = $null
        $s3SK = $null
        $forcePathStyle = $true
        $s3UseAwsTools = $false
        $storageAccountName = $null
        $containerName = $null
        $sasToken = $null

        if ($storageProvider -ieq 'S3') {
            $s3Bucket = $settings['s3BucketName']
            $s3EndpointUrl = $settings['s3EndpointUrl']
            $s3Region = $settings['s3Region']
            $s3AK = $settings['s3AccessKeyId']
            $s3SK = $settings['s3SecretAccessKey']
            $s3Force = $settings['s3ForcePathStyle']
            $s3UseAwsTools = $settings['s3UseAwsTools']

            if ([string]::IsNullOrWhiteSpace($s3Bucket)) { throw 's3BucketName is missing or empty.' }
            if ([string]::IsNullOrWhiteSpace($s3AK) -or [string]::IsNullOrWhiteSpace($s3SK)) { throw 's3AccessKeyId / s3SecretAccessKey missing or empty.' }
            if ([string]::IsNullOrWhiteSpace($s3EndpointUrl)) { throw 's3EndpointUrl is required for S3-compatible storage.' }
            $forcePathStyle = Get-BooleanSetting -Value $s3Force -Default $true
            try { $s3UseAwsTools = [System.Convert]::ToBoolean($s3UseAwsTools) } catch { $s3UseAwsTools = $false }
            if ($parallelDownloadsEnabled -and $s3UseAwsTools) {
                Write-Warning 'Parallel shard downloads require the SigV4 HTTP path; disabling AWS Tools mode for this run.'
                $s3UseAwsTools = $false
            }

            $downloadKey = Combine-StoragePath -Prefix $null -Name $manifestBlobPath
            if ($s3UseAwsTools) {
                try {
                    $client = New-S3Client -EndpointUrl $s3EndpointUrl -Region $s3Region -AccessKeyId $s3AK -SecretAccessKey $s3SK -ForcePathStyle:$forcePathStyle
                    $req = New-Object Amazon.S3.Model.GetObjectRequest -Property @{ BucketName = $s3Bucket; Key = $downloadKey }
                    $resp = $client.GetObject($req)
                    try { $resp.WriteResponseStreamToFile($manifestTempPath, $true) } finally { $resp.Dispose() }
                } catch {
                    Write-Warning "AWS Tools download failed for manifest: $($_.Exception.Message). Falling back to SigV4 HTTP."
                    Invoke-S3HttpDownloadWithRetry -EndpointUrl $s3EndpointUrl -Bucket $s3Bucket -Key $downloadKey -TargetPath $manifestTempPath -Region $s3Region -AccessKeyId $s3AK -SecretAccessKey $s3SK -ForcePathStyle:$forcePathStyle -Activity 'Downloading manifest'
                }
            } else {
                Invoke-S3HttpDownloadWithRetry -EndpointUrl $s3EndpointUrl -Bucket $s3Bucket -Key $downloadKey -TargetPath $manifestTempPath -Region $s3Region -AccessKeyId $s3AK -SecretAccessKey $s3SK -ForcePathStyle:$forcePathStyle -Activity 'Downloading manifest'
            }
        } else {
            $storageAccountName = $settings['storageAccountName']
            $containerName = $settings['containerName']
            $sasToken = $settings['sasToken']
            $client = New-HttpClient
            try {
                $uri = Build-BlobUri -Account $storageAccountName -Container $containerName -Sas $sasToken -BlobName $manifestBlobPath
                Invoke-DownloadWithRetry -Client $client -Uri $uri -TargetPath $manifestTempPath -Activity 'Downloading manifest'
            } finally {
                if ($client) { $client.Dispose() }
            }
        }

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
            Write-Host ("{0} shard(s) require download or refresh." -f $downloadQueue.Count)
        } else {
            Write-Host 'All shards already up to date; verifying manifest and combined file.'
        }

        $storageClient = $null
        $storageHttpClient = $null
        $isS3 = ($storageProvider -ieq 'S3')

        try {
            if ($isS3) {
                $s3Bucket = $settings['s3BucketName']
                $s3EndpointUrl = $settings['s3EndpointUrl']
                $s3Region = $settings['s3Region']
                $s3AK = $settings['s3AccessKeyId']
                $s3SK = $settings['s3SecretAccessKey']
                $s3Force = $settings['s3ForcePathStyle']
                $forcePathStyle = Get-BooleanSetting -Value $s3Force -Default $true
                $useAwsTools = $settings['s3UseAwsTools']
                try { $useAwsTools = [System.Convert]::ToBoolean($useAwsTools) } catch { $useAwsTools = $false }

                if ($downloadQueue.Count -gt 0 -and -not $parallelDownloadsEnabled) {
                    if ($useAwsTools) {
                        $storageClient = New-S3Client -EndpointUrl $s3EndpointUrl -Region $s3Region -AccessKeyId $s3AK -SecretAccessKey $s3SK -ForcePathStyle:$forcePathStyle
                    }
                    $storageHttpClient = @{
                        Endpoint  = $s3EndpointUrl
                        Bucket    = $s3Bucket
                        Region    = $s3Region
                        AccessKey = $s3AK
                        SecretKey = $s3SK
                        ForcePath = $forcePathStyle
                    }
                }
            } else {
                if ($downloadQueue.Count -gt 0 -and -not $parallelDownloadsEnabled) {
                    $storageHttpClient = New-HttpClient
                }
            }

            if ($parallelDownloadsEnabled -and $downloadQueue.Count -gt 0) {
                Write-Host ("Downloading shards with up to {0} concurrent transfer(s)..." -f $effectiveParallelTransfers)
                $remotePrefixForParallel = if ([string]::IsNullOrWhiteSpace($remoteShardPrefix)) { $null } else { $remoteShardPrefix.Replace('\', '/').Trim('/') }
                $parallelDownloadHelpers = if ($isS3) { $parallelS3DownloadHelperList } else { $parallelAzureDownloadHelperList }
                $downloadQueue.ToArray() | ForEach-Object -Parallel {
                    $entry = $PSItem
                    try {
                        if ($null -eq $entry) { return }
                        foreach ($helper in $using:parallelDownloadHelpers) {
                            if (-not (Get-Command $helper.Name -ErrorAction SilentlyContinue)) {
                                Invoke-Expression $helper.Definition
                            }
                        }
                        $name = [string]$entry.Name
                        if ([string]::IsNullOrWhiteSpace($name)) {
                            throw "Parallel shard entry missing name: $(ConvertTo-Json $entry -Compress)"
                        }
                        $expectedHash = ([string]$entry.Sha256).ToLowerInvariant()
                        $expectedSize = [long]$entry.Size

                        $remoteKey = $name.Replace('\', '/').TrimStart('/')
                        if (-not [string]::IsNullOrWhiteSpace($using:remotePrefixForParallel)) {
                            $remoteKey = $using:remotePrefixForParallel + '/' + $remoteKey
                        }
                        $stagingPath = Join-Path -Path $using:downloadTempRoot -ChildPath $name
                        $stagingParent = Split-Path -Path $stagingPath -Parent
                        if ($stagingParent -and -not (Test-Path -LiteralPath $stagingParent)) {
                            [System.IO.Directory]::CreateDirectory($stagingParent) | Out-Null
                        }

                        $activity = ("Downloading shard: {0}" -f $name)
                        if ($using:isS3) {
                            Invoke-S3HttpDownloadWithRetry -EndpointUrl $using:s3EndpointUrl -Bucket $using:s3Bucket -Key $remoteKey -TargetPath $stagingPath -Region $using:s3Region -AccessKeyId $using:s3AK -SecretAccessKey $using:s3SK -ForcePathStyle:$using:forcePathStyle -Activity $activity
                        } else {
                            $client = $null
                            try {
                                $client = New-HttpClient
                                $blobUri = Build-BlobUri -Account $using:storageAccountName -Container $using:containerName -Sas $using:sasToken -BlobName $remoteKey
                                Invoke-DownloadWithRetry -Client $client -Uri $blobUri -TargetPath $stagingPath -Activity $activity
                            } finally {
                                if ($client) { $client.Dispose() }
                            }
                        }

                        $downloadInfo = Get-Item -LiteralPath $stagingPath
                        if ($downloadInfo.Length -ne $expectedSize) {
                            throw "Shard '$name' size mismatch. Expected $expectedSize bytes, got $($downloadInfo.Length)."
                        }

                        $actualHash = Get-FileSha256Lower -Path $stagingPath
                        if ($actualHash -ne $expectedHash) {
                            throw "Shard '$name' checksum mismatch. Expected $expectedHash, got $actualHash."
                        }

                        $finalPath = Join-Path -Path $using:localShardRoot -ChildPath $name
                        $parentDir = Split-Path -Path $finalPath -Parent
                        if ($parentDir -and -not (Test-Path -LiteralPath $parentDir)) {
                            [System.IO.Directory]::CreateDirectory($parentDir) | Out-Null
                        }
                        Move-Item -LiteralPath $stagingPath -Destination $finalPath -Force
                        Write-Host ("Shard '{0}' updated." -f $name)
                    } catch {
                        throw ("Shard '{0}': {1}" -f $entry.name, $_.Exception.Message)
                    }
                } -ThrottleLimit $effectiveParallelTransfers
            } else {
                $downloadIndex = 0
                foreach ($entry in $downloadQueue.ToArray()) {
                    $downloadIndex++
                    if ($null -eq $entry) { continue }
                    $name = [string]$entry.Name
                    if ([string]::IsNullOrWhiteSpace($name)) {
                        throw "Shard entry missing name: $(ConvertTo-Json $entry -Compress)"
                    }
                    $expectedHash = ([string]$entry.Sha256).ToLowerInvariant()
                    $expectedSize = [long]$entry.Size

                    $activity = "Downloading shard $downloadIndex/$($downloadQueue.Count): $name"
                    $remoteKey = Combine-StoragePath -Prefix $remoteShardPrefix -Name $name
                    $stagingPath = Join-Path -Path $downloadTempRoot -ChildPath $name
                    Ensure-Directory (Split-Path -Path $stagingPath -Parent)

                    if ($isS3) {
                        if ($storageClient) {
                            try {
                                $request = New-Object Amazon.S3.Model.GetObjectRequest -Property @{ BucketName = $s3Bucket; Key = $remoteKey }
                                $response = $storageClient.GetObject($request)
                                try { $response.WriteResponseStreamToFile($stagingPath, $true) } finally { $response.Dispose() }
                            } catch {
                                Write-Warning "AWS Tools download failed for shard '$name': $($_.Exception.Message). Falling back to SigV4 HTTP."
                                Invoke-S3HttpDownloadWithRetry -EndpointUrl $storageHttpClient.Endpoint -Bucket $storageHttpClient.Bucket -Key $remoteKey -TargetPath $stagingPath -Region $storageHttpClient.Region -AccessKeyId $storageHttpClient.AccessKey -SecretAccessKey $storageHttpClient.SecretKey -ForcePathStyle:$storageHttpClient.ForcePath -Activity $activity
                            }
                        } else {
                            Invoke-S3HttpDownloadWithRetry -EndpointUrl $storageHttpClient.Endpoint -Bucket $storageHttpClient.Bucket -Key $remoteKey -TargetPath $stagingPath -Region $storageHttpClient.Region -AccessKeyId $storageHttpClient.AccessKey -SecretAccessKey $storageHttpClient.SecretKey -ForcePathStyle:$storageHttpClient.ForcePath -Activity $activity
                        }
                    } else {
                        $blobUri = Build-BlobUri -Account $storageAccountName -Container $containerName -Sas $sasToken -BlobName $remoteKey
                        Invoke-DownloadWithRetry -Client $storageHttpClient -Uri $blobUri -TargetPath $stagingPath -Activity $activity
                    }

                    $downloadInfo = Get-Item -LiteralPath $stagingPath
                    if ($downloadInfo.Length -ne $expectedSize) {
                        throw "Shard '$name' size mismatch. Expected $expectedSize bytes, got $($downloadInfo.Length)."
                    }

                    $actualHash = Get-FileSha256Lower -Path $stagingPath
                    if ($actualHash -ne $expectedHash) {
                        throw "Shard '$name' checksum mismatch. Expected $expectedHash, got $actualHash."
                    }

                    $finalPath = Join-Path -Path $localShardRoot -ChildPath $name
                    Ensure-Directory (Split-Path -Path $finalPath -Parent)
                    Move-Item -LiteralPath $stagingPath -Destination $finalPath -Force
                    Write-Host ("Shard '{0}' updated." -f $name)
                }
            }
        } finally {
            if ($storageClient) { $storageClient.Dispose() }
            if ($storageHttpClient -is [System.Net.Http.HttpClient]) { $storageHttpClient.Dispose() }
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

        $khdbName = if ([string]::IsNullOrWhiteSpace($settings['WeakPasswordsDatabase'])) { 'khdb.txt' } else { $settings['WeakPasswordsDatabase'] }
        $combinedTarget = Join-Path -Path $installPath -ChildPath $khdbName
        $combinedTemp = Join-Path -Path $tmpDir.FullName -ChildPath 'khdb-combined.txt'

        Write-Host "Rebuilding combined KHDB file..."
        Merge-ShardsToFile -Manifest $manifest -ShardsRoot $localShardRoot -TargetPath $combinedTemp
        Validate-KHDBFile -Path $combinedTemp

        if (Test-Path -LiteralPath $combinedTarget) {
            $ts = Get-Date -Format 'yyyyMMdd-HHmmss'
            $backupPath = Join-Path -Path $installPath -ChildPath ("$khdbName.bak-$ts")
            Copy-Item -LiteralPath $combinedTarget -Destination $backupPath -Force
            Write-Host ("Existing KHDB backed up to {0}" -f $backupPath)

            # Each run adds one full-size backup; keep only the most recent few so a recurring
            # scheduled job doesn't silently accumulate backups until the disk fills up.
            $backupRetentionCount = 5
            $staleBackups = Get-ChildItem -LiteralPath $installPath -Filter "$khdbName.bak-*" -File -ErrorAction SilentlyContinue |
                Sort-Object Name -Descending | Select-Object -Skip $backupRetentionCount
            foreach ($stale in $staleBackups) {
                try { Remove-Item -LiteralPath $stale.FullName -Force } catch { Write-Warning "Could not remove old backup '$($stale.FullName)': $($_.Exception.Message)" }
            }
        }

        Move-Item -LiteralPath $combinedTemp -Destination $combinedTarget -Force
        Write-Host ("KHDB merged file refreshed at {0}" -f $combinedTarget)
        Write-Host "KHDB update completed successfully."
    } catch {
        Write-Error ("KHDB update failed: {0}" -f $_.Exception.Message)
        throw
    } finally {
        try { if ($tmpDir -and (Test-Path $tmpDir.FullName)) { Remove-Item -Path $tmpDir.FullName -Recurse -Force } } catch {}
        Stop-ElysiumTranscript
    }
}
