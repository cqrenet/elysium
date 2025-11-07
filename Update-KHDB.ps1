##################################################
##   ____ ___  ____  _____   _   _ _____ _____  ##
##  / ___/ _ \|  _ \| ____| | \ | | ____|_   _| ##
## | |  | | | | |_) |  _|   |  \| |  _|   | |   ##
## | |__| |_| |  _ <| |___ _| |\  | |___  | |   ##
##  \____\__\_\_| \_\_____(_)_| \_|_____| |_|   ##
##################################################
## Project: Elysium                             ##
## File: Update-KHDB.ps1                        ##
## Version: 2.0.0                               ##
## Support: support@cqre.net                    ##
##################################################

<#
.SYNOPSIS
Known-hashes database updater for the Elysium AD password testing tool.

.DESCRIPTION
Downloads a sharded KHDB manifest, performs incremental shard updates, validates
checksums, and atomically refreshes the merged khdb.txt for downstream scripts.
Supports Azure Blob Storage (via SAS) and S3-compatible endpoints (SigV4).
#>

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

$scriptRoot = $PSScriptRoot

function Start-UpdateTranscript {
    param([string]$BasePath)
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
            if ($kv.Count -eq 2) {
                $settings[$kv[0].Trim()] = $kv[1].Trim().Trim("'")
            }
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
    Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue
    $client = [System.Net.Http.HttpClient]::new()
    $client.Timeout = [TimeSpan]::FromSeconds(600)
    $client.DefaultRequestHeaders.UserAgent.ParseAdd('Elysium/2.0 (+Update-KHDB)')
    return $client
}

function Build-BlobUri {
    param(
        [string]$Account,
        [string]$Container,
        [string]$Sas,
        [string]$BlobName
    )

    if ([string]::IsNullOrWhiteSpace($Account)) { throw 'storageAccountName is missing or empty.' }
    if ([string]::IsNullOrWhiteSpace($Container)) { throw 'containerName is missing or empty.' }
    if ([string]::IsNullOrWhiteSpace($Sas)) { throw 'sasToken is missing or empty.' }
    if ([string]::IsNullOrWhiteSpace($BlobName)) { throw 'BlobName cannot be empty.' }

    $sas = $Sas.Trim()
    if (-not $sas.StartsWith('?')) { $sas = '?' + $sas }
    $normalizedBlob = $BlobName.Replace('\', '/').TrimStart('/')
    $uriBuilder = [System.UriBuilder]::new("https://$Account.blob.core.windows.net/$Container/$normalizedBlob")
    $uriBuilder.Query = $sas.TrimStart('?')
    return $uriBuilder.Uri.AbsoluteUri
}

function Ensure-AWSS3Module {
    try { $null = [Amazon.S3.AmazonS3Client]; return } catch {}
    try { Import-Module -Name AWS.Tools.S3 -ErrorAction Stop; return } catch {}
    try { Import-Module -Name AWSPowerShell.NetCore -ErrorAction Stop; return } catch {}
    throw "AWS Tools for PowerShell not found. Install with: Install-Module AWS.Tools.S3 -Scope CurrentUser"
}

function New-S3Client {
    param(
        [string]$EndpointUrl,
        [string]$Region,
        [string]$AccessKeyId,
        [string]$SecretAccessKey,
        [bool]$ForcePathStyle = $true
    )

    Ensure-AWSS3Module
    $creds = New-Object Amazon.Runtime.BasicAWSCredentials($AccessKeyId, $SecretAccessKey)
    $cfg = New-Object Amazon.S3.AmazonS3Config
    if ($EndpointUrl) { $cfg.ServiceURL = $EndpointUrl }
    if ($Region) { try { $cfg.RegionEndpoint = [Amazon.RegionEndpoint]::GetBySystemName($Region) } catch {} }
    $cfg.ForcePathStyle = [bool]$ForcePathStyle
    return (New-Object Amazon.S3.AmazonS3Client($creds, $cfg))
}

function Get-Bytes([string]$s) { return [System.Text.Encoding]::UTF8.GetBytes($s) }
function Get-HashHex([byte[]]$bytes) {
    if ($null -eq $bytes) { $bytes = [byte[]]@() }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $ms = New-Object System.IO.MemoryStream -ArgumentList (,$bytes)
        try {
            $hash = $sha.ComputeHash([System.IO.Stream]$ms)
        } finally { $ms.Dispose() }
        return ([BitConverter]::ToString($hash)).Replace('-', '').ToLowerInvariant()
    } finally { $sha.Dispose() }
}
function HmacSha256([byte[]]$key, [string]$data) {
    $h = [System.Security.Cryptography.HMACSHA256]::new($key)
    try {
        $b = [System.Text.Encoding]::UTF8.GetBytes($data)
        $ms = New-Object System.IO.MemoryStream -ArgumentList (,$b)
        try {
            return $h.ComputeHash([System.IO.Stream]$ms)
        } finally { $ms.Dispose() }
    } finally { $h.Dispose() }
}
function GetSignatureKey([string]$secret, [string]$dateStamp, [string]$regionName, [string]$serviceName) {
    $kDate = HmacSha256 (Get-Bytes ('AWS4' + $secret)) $dateStamp
    $kRegion = HmacSha256 $kDate $regionName
    $kService = HmacSha256 $kRegion $serviceName
    HmacSha256 $kService 'aws4_request'
}
function UriEncode([string]$data, [bool]$encodeSlash) {
    $enc = [System.Uri]::EscapeDataString($data)
    if (-not $encodeSlash) { $enc = $enc -replace '%2F', '/' }
    return $enc
}
function BuildCanonicalPath([System.Uri]$uri) {
    $segments = $uri.AbsolutePath.Split('/')
    $encoded = @()
    foreach ($s in $segments) { $encoded += (UriEncode $s $false) }
    $path = ($encoded -join '/')
    if (-not $path.StartsWith('/')) { $path = '/' + $path }
    return $path
}
function ToHex([byte[]]$b) { ([BitConverter]::ToString($b)).Replace('-', '').ToLowerInvariant() }
function BuildAuthHeaders($method, [System.Uri]$uri, [string]$region, [string]$accessKey, [string]$secretKey, [string]$payloadHash) {
    $algorithm = 'AWS4-HMAC-SHA256'
    $timestamp = (Get-Date).ToUniversalTime()
    $amzDate = $timestamp.ToString('yyyyMMddTHHmmssZ')
    $dateStamp = $timestamp.ToString('yyyyMMdd')
    $hostHeader = $uri.Host
    if (-not $uri.IsDefaultPort) { $hostHeader = "${hostHeader}:$($uri.Port)" }
    $canonicalUri = BuildCanonicalPath $uri
    $canonicalQueryString = ''
    $canonicalHeaders = "host:$hostHeader`n" + "x-amz-content-sha256:$payloadHash`n" + "x-amz-date:$amzDate`n"
    $signedHeaders = 'host;x-amz-content-sha256;x-amz-date'
    $canonicalRequest = "$method`n$canonicalUri`n$canonicalQueryString`n$canonicalHeaders`n$signedHeaders`n$payloadHash"
    $credentialScope = "$dateStamp/$region/s3/aws4_request"
    $stringToSign = "$algorithm`n$amzDate`n$credentialScope`n$((Get-HashHex (Get-Bytes $canonicalRequest)))"
    $signingKey = GetSignatureKey $secretKey $dateStamp $region 's3'
    $signature = ToHex (HmacSha256 $signingKey $stringToSign)
    $authHeader = "$algorithm Credential=$accessKey/$credentialScope, SignedHeaders=$signedHeaders, Signature=$signature"
    @{
        'x-amz-date'            = $amzDate
        'x-amz-content-sha256'  = $payloadHash
        'Authorization'         = $authHeader
    }
}
function BuildS3Uri([string]$endpointUrl, [string]$bucket, [string]$key, [bool]$forcePathStyle) {
    $base = [System.Uri]$endpointUrl
    $builder = [System.UriBuilder]::new($base)
    $normalizedKey = $key.Replace('\', '/').TrimStart('/')
    if ($forcePathStyle) {
        $path = $builder.Path.TrimEnd('/')
        if ([string]::IsNullOrEmpty($path)) { $path = '/' }
        $builder.Path = ($path.TrimEnd('/') + '/' + $bucket + '/' + $normalizedKey)
    } else {
        $builder.Host = "$bucket." + $builder.Host
        $path = $builder.Path.TrimEnd('/')
        if ([string]::IsNullOrEmpty($path)) { $path = '/' }
        $builder.Path = ($path.TrimEnd('/') + '/' + $normalizedKey)
    }
    return $builder.Uri
}

function Invoke-S3HttpDownloadWithRetry {
    param(
        [string]$EndpointUrl,
        [string]$Bucket,
        [string]$Key,
        [string]$TargetPath,
        [string]$Region,
        [string]$AccessKeyId,
        [string]$SecretAccessKey,
        [bool]$ForcePathStyle,
        [string]$Activity
    )

    Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue
    [System.Net.Http.HttpClient]$client = [System.Net.Http.HttpClient]::new()
    $retries = 5
    $delay = 2
    try {
        for ($attempt = 0; $attempt -lt $retries; $attempt++) {
            $request = $null
            try {
                $uri = BuildS3Uri -endpointUrl $EndpointUrl -bucket $Bucket -key $Key -forcePathStyle $ForcePathStyle
                $payloadHash = (Get-HashHex (Get-Bytes ''))
                $headers = BuildAuthHeaders -method 'GET' -uri $uri -region $Region -accessKey $AccessKeyId -secretKey $SecretAccessKey -payloadHash $payloadHash
                $request = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Get, $uri)
                foreach ($kvp in $headers.GetEnumerator()) {
                    $request.Headers.TryAddWithoutValidation($kvp.Key, $kvp.Value) | Out-Null
                }

                $response = $client.SendAsync($request, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
                $null = $response.EnsureSuccessStatusCode()

                $totalBytes = $response.Content.Headers.ContentLength
                $stream = $response.Content.ReadAsStreamAsync().Result
                $tmpPath = $TargetPath
                $fs = [System.IO.File]::Create($tmpPath)
                try {
                    $buffer = New-Object byte[] 8192
                    $totalRead = 0
                    while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                        $fs.Write($buffer, 0, $read)
                        $totalRead += $read
                        if ($totalBytes) {
                            $pct = ($totalRead * 100.0) / $totalBytes
                            Write-Progress -Activity $Activity -Status ("{0:N2}% Complete" -f $pct) -PercentComplete $pct
                        } else {
                            Write-Progress -Activity $Activity -Status ("Downloaded {0:N0} bytes" -f $totalRead) -PercentComplete 0
                        }
                    }
                } finally {
                    $fs.Close()
                    $stream.Close()
                }

                if ($response) { $response.Dispose() }
                Write-Progress -Activity $Activity -Completed -Status 'Completed'
                return
            } catch {
                if ($attempt -lt ($retries - 1)) {
                    Write-Warning "Download of '$Key' failed (attempt $($attempt + 1)/$retries): $($_.Exception.Message). Retrying in ${delay}s..."
                    Start-Sleep -Seconds $delay
                    $delay = [Math]::Min($delay * 2, 30)
                } else {
                    throw
                }
            } finally {
                if ($request) { $request.Dispose() }
            }
        }
    } finally {
        $client.Dispose()
    }
}

function Invoke-DownloadWithRetry {
    param(
        [System.Net.Http.HttpClient]$Client,
        [string]$Uri,
        [string]$TargetPath,
        [string]$Activity
    )

    $retries = 5
    $delay = 2
    for ($attempt = 0; $attempt -lt $retries; $attempt++) {
        try {
            $response = $Client.GetAsync($Uri, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).Result
            if (-not $response.IsSuccessStatusCode) {
                $code = [int]$response.StatusCode
                if (($code -ge 500 -and $code -lt 600) -or $code -eq 429 -or $code -eq 408) { throw "Transient HTTP error $code" }
                throw "HTTP error $code"
            }

            $totalBytes = $response.Content.Headers.ContentLength
            $stream = $response.Content.ReadAsStreamAsync().Result
            $fs = [System.IO.File]::Create($TargetPath)
            try {
                $buffer = New-Object byte[] 8192
                $totalRead = 0
                while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    $fs.Write($buffer, 0, $read)
                    $totalRead += $read
                    if ($totalBytes) {
                        $pct = ($totalRead * 100.0) / $totalBytes
                        Write-Progress -Activity $Activity -Status ("{0:N2}% Complete" -f $pct) -PercentComplete $pct
                    } else {
                        Write-Progress -Activity $Activity -Status ("Downloaded {0:N0} bytes" -f $totalRead) -PercentComplete 0
                    }
                }
            } finally {
                $fs.Close()
                $stream.Close()
            }

            Write-Progress -Activity $Activity -Completed -Status 'Completed'
            return
        } catch {
            if ($attempt -lt ($retries - 1)) {
                Write-Warning "Download of '$Uri' failed (attempt $($attempt + 1)/$retries): $($_.Exception.Message). Retrying in ${delay}s..."
                Start-Sleep -Seconds $delay
                $delay = [Math]::Min($delay * 2, 30)
            } else {
                throw
            }
        }
    }
}

function Get-FileSha256Lower {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "File not found: $Path" }
    return (Get-FileHash -Path $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Ensure-Directory {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }
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

function Get-RelativePath {
    param(
        [string]$BasePath,
        [string]$FullPath
    )

    $base = (Resolve-Path -LiteralPath $BasePath).ProviderPath
    $full = (Resolve-Path -LiteralPath $FullPath).ProviderPath
    if (-not $base.EndsWith([System.IO.Path]::DirectorySeparatorChar)) {
        $base = $base + [System.IO.Path]::DirectorySeparatorChar
    }

    $baseUri = New-Object System.Uri($base, [System.UriKind]::Absolute)
    $fullUri = New-Object System.Uri($full, [System.UriKind]::Absolute)
    $relativeUri = $baseUri.MakeRelativeUri($fullUri)
    $relativePath = [System.Uri]::UnescapeDataString($relativeUri.ToString())
    return $relativePath.Replace('/', [System.IO.Path]::DirectorySeparatorChar)
}

function Combine-StoragePath {
    param(
        [string]$Prefix,
        [string]$Name
    )

    $cleanName = $Name.Replace('\', '/').TrimStart('/')
    if ([string]::IsNullOrWhiteSpace($Prefix)) { return $cleanName }
    $normalizedPrefix = $Prefix.Replace('\', '/').Trim('/')
    if ([string]::IsNullOrEmpty($normalizedPrefix)) { return $cleanName }
    return "$normalizedPrefix/$cleanName"
}

function Load-Manifest {
    param([string]$Path)
    $raw = Get-Content -LiteralPath $Path -Encoding UTF8 -Raw
    return $raw | ConvertFrom-Json
}

function Validate-Manifest {
    param([psobject]$Manifest)

    if (-not $Manifest) { throw 'Manifest is empty or invalid JSON.' }
    if (-not $Manifest.shards) { throw 'Manifest does not contain a shards collection.' }

    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $Manifest.shards) {
        if (-not $entry) { throw 'Manifest contains null shard entries.' }
        $name = [string]$entry.name
        if ([string]::IsNullOrWhiteSpace($name)) { throw 'Manifest shard entry is missing name.' }
        $hash = [string]$entry.sha256
        if ([string]::IsNullOrWhiteSpace($hash) -or $hash.Length -ne 64) { throw "Manifest shard '$name' is missing a valid sha256." }
        $sizeValue = [string]$entry.size
        $sizeParsed = 0L
        if (-not [long]::TryParse($sizeValue, [ref]$sizeParsed) -or $sizeParsed -lt 0) {
            throw "Manifest shard '$name' has invalid size."
        }
        if (-not $seen.Add($name)) { throw "Manifest contains duplicate shard name '$name'." }
    }

    if ($Manifest.shardSize -and [int]$Manifest.shardSize -ne 2) {
        throw "Manifest shardSize $($Manifest.shardSize) is not supported. Expected shardSize 2."
    }
}

function Merge-ShardsToFile {
    param(
        [psobject]$Manifest,
        [string]$ShardsRoot,
        [string]$TargetPath
    )

    $encoding = New-Object System.Text.UTF8Encoding($false)
    $writer = New-Object System.IO.StreamWriter($TargetPath, $false, $encoding)
    try {
        foreach ($entry in ($Manifest.shards | Sort-Object name)) {
            $relative = [string]$entry.name
            $shardPath = Join-Path -Path $ShardsRoot -ChildPath $relative
            if (-not (Test-Path -LiteralPath $shardPath)) {
                throw "Missing shard on disk: $relative"
            }
            $reader = New-Object System.IO.StreamReader($shardPath, [System.Text.Encoding]::UTF8, $true)
            try {
                while (($line = $reader.ReadLine()) -ne $null) {
                    $trimmed = $line.Trim()
                    if ($trimmed.Length -gt 0) {
                        $writer.WriteLine($trimmed)
                    }
                }
            } finally {
                $reader.Dispose()
            }
        }
    } finally {
        $writer.Dispose()
    }
}

function Validate-KHDBFile {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { throw "Validation failed: $Path not found." }

    $regex = '^[0-9A-Fa-f]{32}(:\d+)?$'
    $lineNumber = 0
    $previous = $null
    $duplicates = 0
    $reader = New-Object System.IO.StreamReader($Path, [System.Text.Encoding]::UTF8, $true)
    try {
        while (($line = $reader.ReadLine()) -ne $null) {
            $lineNumber++
            $trimmed = $line.Trim()
            if ($trimmed.Length -eq 0) { continue }
            if ($trimmed -notmatch $regex) {
                throw "Validation failed: unexpected format at line $lineNumber ('$trimmed')."
            }
            $normalized = $trimmed.ToUpperInvariant()
            if ($previous -and $normalized -lt $previous) {
                Write-Warning ("Validation warning: line {0} is out of order." -f $lineNumber)
            }
            if ($normalized -eq $previous) { $duplicates++ }
            $previous = $normalized
        }
    } finally {
        $reader.Dispose()
    }

    if ($lineNumber -eq 0) { throw 'Validation failed: KHDB file is empty.' }
    if ($duplicates -gt 0) {
        Write-Warning ("Validation warning: detected {0} duplicate hash entries (file remains unchanged)." -f $duplicates)
    }
}

function Remove-EmptyDirectories {
    param([string]$Root)

    if (-not (Test-Path -LiteralPath $Root)) { return }
    Get-ChildItem -LiteralPath $Root -Directory -Recurse | Sort-Object FullName -Descending | ForEach-Object {
        $childItems = Get-ChildItem -LiteralPath $_.FullName -Force
        if (-not $childItems) {
            Remove-Item -LiteralPath $_.FullName -Force
        }
    }
}

function Update-KHDB {
    Start-UpdateTranscript -BasePath $scriptRoot
    try {
        $settings = Read-ElysiumSettings
        $installPath = Get-InstallationPath $settings
        Ensure-Directory $installPath

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

        $downloadQueue = New-Object System.Collections.Generic.List[psobject]
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
                $downloadQueue.Add($entry)
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

                if ($downloadQueue.Count -gt 0) {
                    if ($useAwsTools) {
                        $storageClient = New-S3Client -EndpointUrl $s3EndpointUrl -Region $s3Region -AccessKeyId $s3AK -SecretAccessKey $s3SK -ForcePathStyle:$forcePathStyle
                    } else {
                        $storageHttpClient = @{
                            Endpoint    = $s3EndpointUrl
                            Bucket      = $s3Bucket
                            Region      = $s3Region
                            AccessKey   = $s3AK
                            SecretKey   = $s3SK
                            ForcePath   = $forcePathStyle
                        }
                    }
                }
            } else {
                if ($downloadQueue.Count -gt 0) {
                    $storageHttpClient = New-HttpClient
                }
            }

            $downloadIndex = 0
            foreach ($entry in $downloadQueue) {
                $downloadIndex++
                $name = [string]$entry.name
                $expectedHash = ([string]$entry.sha256).ToLowerInvariant()
                $expectedSize = 0L
                [void][long]::TryParse([string]$entry.size, [ref]$expectedSize)

                $activity = "Downloading shard $downloadIndex/$($downloadQueue.Count): $name"
                $remoteKey = Combine-StoragePath -Prefix $remoteShardPrefix -Name $name
                $stagingPath = Join-Path -Path $downloadTempRoot -ChildPath $name
                Ensure-Directory (Split-Path -Path $stagingPath -Parent)

                if ($isS3) {
                    if ($storageClient) {
                        try {
                            $request = New-Object Amazon.S3.Model.GetObjectRequest -Property @{ BucketName = $settings['s3BucketName']; Key = $remoteKey }
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
                    $storageAccountName = $settings['storageAccountName']
                    $containerName = $settings['containerName']
                    $sasToken = $settings['sasToken']
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
        }

        Move-Item -LiteralPath $combinedTemp -Destination $combinedTarget -Force
        Write-Host ("KHDB merged file refreshed at {0}" -f $combinedTarget)
        Write-Host "KHDB update completed successfully."
    } catch {
        Write-Error ("KHDB update failed: {0}" -f $_.Exception.Message)
        throw
    } finally {
        try { if ($tmpDir -and (Test-Path $tmpDir.FullName)) { Remove-Item -Path $tmpDir.FullName -Recurse -Force } } catch {}
        Stop-UpdateTranscript
    }
}

Update-KHDB
Write-Host "Script execution completed."
