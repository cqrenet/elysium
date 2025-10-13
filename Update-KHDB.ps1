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
This script downloads khdb.txt.zip from the designated storage (Azure Blob or S3-compatible), validates and decompresses it, and atomically updates the current version with backup and logging.
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

# Native S3 SigV4 (no AWS Tools) helpers
function Get-Bytes([string]$s) { return [System.Text.Encoding]::UTF8.GetBytes($s) }
function Get-HashHex([byte[]]$bytes) { $sha=[System.Security.Cryptography.SHA256]::Create(); try { ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant() } finally { $sha.Dispose() } }
function HmacSha256([byte[]]$key, [string]$data) { $h=[System.Security.Cryptography.HMACSHA256]::new($key); try { $h.ComputeHash((Get-Bytes $data)) } finally { $h.Dispose() } }
function GetSignatureKey([string]$secret, [string]$dateStamp, [string]$regionName, [string]$serviceName) {
    $kDate = HmacSha256 (Get-Bytes ('AWS4' + $secret)) $dateStamp
    $kRegion = HmacSha256 $kDate $regionName
    $kService = HmacSha256 $kRegion $serviceName
    HmacSha256 $kService 'aws4_request'
}
function UriEncode([string]$data, [bool]$encodeSlash) { $enc=[System.Uri]::EscapeDataString($data); if (-not $encodeSlash) { $enc = $enc -replace '%2F','/' }; $enc }
function BuildCanonicalPath([System.Uri]$uri) { $segments=$uri.AbsolutePath.Split('/'); $encoded=@(); foreach($s in $segments){ $encoded += (UriEncode $s $false) }; $p=($encoded -join '/'); if (-not $p.StartsWith('/')){ $p='/' + $p }; $p }
function ToHex([byte[]]$b) { ([BitConverter]::ToString($b)).Replace('-', '').ToLowerInvariant() }
function BuildAuthHeaders($method, [System.Uri]$uri, [string]$region, [string]$accessKey, [string]$secretKey, [string]$payloadHash) {
    $algorithm = 'AWS4-HMAC-SHA256'
    $amzdate = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $datestamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd')
    $hostHeader = $uri.Host; if (-not $uri.IsDefaultPort) { $hostHeader = "$hostHeader:$($uri.Port)" }
    $canonicalUri = BuildCanonicalPath $uri
    $canonicalQueryString = ''
    $canonicalHeaders = "host:$hostHeader`n" + "x-amz-content-sha256:$payloadHash`n" + "x-amz-date:$amzdate`n"
    $signedHeaders = 'host;x-amz-content-sha256;x-amz-date'
    $canonicalRequest = "$method`n$canonicalUri`n$canonicalQueryString`n$canonicalHeaders`n$signedHeaders`n$payloadHash"
    $credentialScope = "$datestamp/$region/s3/aws4_request"
    $stringToSign = "$algorithm`n$amzdate`n$credentialScope`n$((Get-HashHex (Get-Bytes $canonicalRequest)))"
    $signingKey = GetSignatureKey $secretKey $datestamp $region 's3'
    $signature = ToHex (HmacSha256 $signingKey $stringToSign)
    $authHeader = "$algorithm Credential=$accessKey/$credentialScope, SignedHeaders=$signedHeaders, Signature=$signature"
    @{ 'x-amz-date' = $amzdate; 'x-amz-content-sha256' = $payloadHash; 'Authorization' = $authHeader }
}
function BuildS3Uri([string]$endpointUrl, [string]$bucket, [string]$key, [bool]$forcePathStyle) {
    $base=[System.Uri]$endpointUrl; $ub=[System.UriBuilder]::new($base)
    if ($forcePathStyle) { $p=$ub.Path.TrimEnd('/'); if ([string]::IsNullOrEmpty($p)){ $p='/' }; $ub.Path = ($p.TrimEnd('/') + '/' + $bucket + '/' + $key) }
    else { $ub.Host = "$bucket." + $ub.Host; $p=$ub.Path.TrimEnd('/'); if ([string]::IsNullOrEmpty($p)){ $p='/' }; $ub.Path = ($p.TrimEnd('/') + '/' + $key) }
    $ub.Uri
}
function Invoke-S3HttpDownloadWithRetry([string]$endpointUrl, [string]$bucket, [string]$key, [string]$targetPath, [string]$region, [string]$ak, [string]$sk, [bool]$forcePathStyle) {
    Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue
    $client = [System.Net.Http.HttpClient]::new()
    $retries=5; $delay=2
    try {
        for($i=0;$i -lt $retries;$i++){
            try {
                $uri = BuildS3Uri -endpointUrl $endpointUrl -bucket $bucket -key $key -forcePathStyle $forcePathStyle
                $payloadHash = (Get-HashHex (Get-Bytes ''))
                $req = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Get, $uri)
                $hdrs = BuildAuthHeaders -method 'GET' -uri $uri -region $region -accessKey $ak -secretKey $sk -payloadHash $payloadHash
                $req.Headers.TryAddWithoutValidation('x-amz-date', $hdrs['x-amz-date']) | Out-Null
                $req.Headers.TryAddWithoutValidation('Authorization', $hdrs['Authorization']) | Out-Null
                $req.Headers.TryAddWithoutValidation('x-amz-content-sha256', $hdrs['x-amz-content-sha256']) | Out-Null
                $resp = $client.SendAsync($req).Result
                if (-not $resp.IsSuccessStatusCode) { throw "HTTP $([int]$resp.StatusCode) $($resp.ReasonPhrase)" }
                $totalBytes = $resp.Content.Headers.ContentLength
                $stream = $resp.Content.ReadAsStreamAsync().Result
                $fs = [System.IO.File]::Create($targetPath)
                try {
                    $buffer = New-Object byte[] 8192
                    $totalRead = 0
                    while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                        $fs.Write($buffer, 0, $read)
                        $totalRead += $read
                        if ($totalBytes) { $pct = ($totalRead * 100.0) / $totalBytes; Write-Progress -Activity "Downloading khdb.txt.zip" -Status ("{0:N2}% Complete" -f $pct) -PercentComplete $pct } else { Write-Progress -Activity "Downloading khdb.txt.zip" -Status ("Downloaded {0:N0} bytes" -f $totalRead) -PercentComplete 0 }
                    }
                } finally { $fs.Close(); $stream.Close() }
                if ($resp) { $resp.Dispose() }
                return
            } catch {
                if ($i -lt ($retries - 1)) { Write-Warning "Download failed (attempt $($i+1)/$retries): $($_.Exception.Message). Retrying in ${delay}s..."; Start-Sleep -Seconds $delay; $delay=[Math]::Min($delay*2,30) }
                else { throw }
            } finally { if ($req){ $req.Dispose() } }
        }
    } finally { $client.Dispose() }
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

        $storageProvider = $settings['StorageProvider']
        if ([string]::IsNullOrWhiteSpace($storageProvider)) { $storageProvider = 'Azure' }

        $client = $null
        $s3Bucket = $settings['s3BucketName']
        $s3EndpointUrl = $settings['s3EndpointUrl']
        $s3Region = $settings['s3Region']
        $s3AK = $settings['s3AccessKeyId']
        $s3SK = $settings['s3SecretAccessKey']
        $s3Force = $settings['s3ForcePathStyle']
        $s3UseAwsTools = $settings['s3UseAwsTools']
        try { $s3Force = [System.Convert]::ToBoolean($s3Force) } catch { $s3Force = $true }
        try { $s3UseAwsTools = [System.Convert]::ToBoolean($s3UseAwsTools) } catch { $s3UseAwsTools = $false }

        $tmpDir = New-Item -ItemType Directory -Path ([System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "elysium-khdb-" + [System.Guid]::NewGuid())) -Force
        $zipPath = Join-Path -Path $tmpDir.FullName -ChildPath 'khdb.txt.zip'
        $extractDir = Join-Path -Path $tmpDir.FullName -ChildPath 'extract'
        New-Item -ItemType Directory -Path $extractDir -Force | Out-Null

        if ($storageProvider -ieq 'S3') {
            if ([string]::IsNullOrWhiteSpace($s3Bucket)) { throw 's3BucketName is missing or empty.' }
            if ([string]::IsNullOrWhiteSpace($s3AK) -or [string]::IsNullOrWhiteSpace($s3SK)) { throw 's3AccessKeyId / s3SecretAccessKey missing or empty.' }
            if ([string]::IsNullOrWhiteSpace($s3EndpointUrl)) { throw 's3EndpointUrl is required for S3-compatible storage.' }
            if ($s3UseAwsTools) {
                try {
                    $s3Client = New-S3Client -EndpointUrl $s3EndpointUrl -Region $s3Region -AccessKeyId $s3AK -SecretAccessKey $s3SK -ForcePathStyle:$s3Force
                    Write-Host "Downloading KHDB from S3-compatible storage (AWS Tools)..."
                    # Use AWS SDK stream method into file for progress parity
                    $req = New-Object Amazon.S3.Model.GetObjectRequest -Property @{ BucketName = $s3Bucket; Key = 'khdb.txt.zip' }
                    $resp = $s3Client.GetObject($req)
                    try { $resp.WriteResponseStreamToFile($zipPath, $true) } finally { $resp.Dispose() }
                } catch {
                    Write-Warning "AWS Tools path failed or not available. Falling back to native HTTP (SigV4). Details: $($_.Exception.Message)"
                    Write-Host "Downloading KHDB from S3-compatible storage..."
                    Invoke-S3HttpDownloadWithRetry -endpointUrl $s3EndpointUrl -bucket $s3Bucket -key 'khdb.txt.zip' -targetPath $zipPath -region $s3Region -ak $s3AK -sk $s3SK -forcePathStyle:$s3Force
                }
            } else {
                Write-Host "Downloading KHDB from S3-compatible storage..."
                Invoke-S3HttpDownloadWithRetry -endpointUrl $s3EndpointUrl -bucket $s3Bucket -key 'khdb.txt.zip' -targetPath $zipPath -region $s3Region -ak $s3AK -sk $s3SK -forcePathStyle:$s3Force
            }
        } else {
            $storageAccountName = $settings['storageAccountName']
            $containerName = $settings['containerName']
            $sasToken = $settings['sasToken']
            $uri = Build-BlobUri -account $storageAccountName -container $containerName -sas $sasToken
            $client = New-HttpClient
            Write-Host "Downloading KHDB from Azure Blob Storage..."
            Invoke-DownloadWithRetry -client $client -uri $uri -targetPath $zipPath
        }
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
