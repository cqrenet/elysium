##################################################
##   ____ ___  ____  _____   _   _ _____ _____  ##
##  / ___/ _ \|  _ \| ____| | \ | | ____|_   _| ##
## | |  | | | | |_) |  _|   |  \| |  _|   | |   ##
## | |__| |_| |  _ <| |___ _| |\  | |___  | |   ##
##  \____\__\_\_| \_\_____(_)_| \_|_____| |_|   ##
##################################################
## Project: Elysium                             ##
## File: Extract-NTLMHashes.ps1                 ##
## Version: 1.2.1                               ##
## Support: support@cqre.net                    ##
##################################################

<#
#Requires -Modules DSInternals
.SYNOPSIS
Script for extracting NTLM hashes from live AD for further analysis.

.DESCRIPTION
This script will connect to selected domain (defined in ElysiumSettings.txt) using account with AD replication privileges and extract NTLM hashes from all active accounts. It will then compress and encrypt the resulting file, uploads it to designated Azure Storage account, checks for validity and then deletes everything. The hashes are extracted without usernames to minimise the sensitivity of the operation. Encryption is done with AES and passphrase that was defined in environment variable during first run.
#>

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$scriptRoot = $PSScriptRoot

function Start-ExtractTranscript {
    param([string]$BasePath)
    try {
        $logsDir = Join-Path -Path $BasePath -ChildPath 'Reports/logs'
        if (-not (Test-Path $logsDir)) { New-Item -Path $logsDir -ItemType Directory -Force | Out-Null }
        $ts = Get-Date -Format 'yyyyMMdd-HHmmss'
        $logPath = Join-Path -Path $logsDir -ChildPath "extract-hashes-$ts.log"
        Start-Transcript -Path $logPath -Force | Out-Null
    } catch {
        Write-Warning "Could not start transcript: $($_.Exception.Message)"
    }
}

function Stop-ExtractTranscript { try { Stop-Transcript | Out-Null } catch {} }

Start-ExtractTranscript -BasePath $scriptRoot
try {
    # Import settings
Write-Host "Loading settings..."
$ElysiumSettings = @{}
$settingsPath = Join-Path -Path $scriptRoot -ChildPath "ElysiumSettings.txt"

if (-not (Test-Path $settingsPath)) {
    Write-Error "Settings file not found at $settingsPath"
    exit
}

Get-Content $settingsPath | ForEach-Object {
    if (-not [string]::IsNullOrWhiteSpace($_) -and -not $_.StartsWith("#")) {
        $keyValue = $_ -split '=', 2
        if ($keyValue.Count -eq 2) {
            $ElysiumSettings[$keyValue[0].Trim()] = $keyValue[1].Trim()
        }
    }
}

function Normalize-ReportPath([string]$p) {
    if ([string]::IsNullOrWhiteSpace($p)) { return (Join-Path -Path $scriptRoot -ChildPath 'Reports') }
    if ([System.IO.Path]::IsPathRooted($p)) { return $p }
    return (Join-Path -Path $scriptRoot -ChildPath $p)
}

# Storage provider selection (Azure by default)
$storageProvider = $ElysiumSettings['StorageProvider']
if ([string]::IsNullOrWhiteSpace($storageProvider)) { $storageProvider = 'Azure' }

# Azure settings
$storageAccountName = $ElysiumSettings['storageAccountName']
$containerName = $ElysiumSettings['containerName']
$sasToken = $ElysiumSettings['sasToken']

# S3-compatible settings
$s3EndpointUrl     = $ElysiumSettings['s3EndpointUrl']
$s3Region          = $ElysiumSettings['s3Region']
$s3BucketName      = $ElysiumSettings['s3BucketName']
$s3AccessKeyId     = $ElysiumSettings['s3AccessKeyId']
$s3SecretAccessKey = $ElysiumSettings['s3SecretAccessKey']
$s3ForcePathStyle  = $ElysiumSettings['s3ForcePathStyle']
$s3UseAwsTools     = $ElysiumSettings['s3UseAwsTools']
if ([string]::IsNullOrWhiteSpace($s3Region)) { $s3Region = 'us-east-1' }
try { $s3ForcePathStyle = [System.Convert]::ToBoolean($s3ForcePathStyle) } catch { $s3ForcePathStyle = $true }
try { $s3UseAwsTools = [System.Convert]::ToBoolean($s3UseAwsTools) } catch { $s3UseAwsTools = $false }

function Ensure-AWSS3Module {
    # Ensure AWS SDK types are available via AWS Tools for PowerShell
    try {
        $null = [Amazon.S3.AmazonS3Client]
        return
    } catch {
        try { Import-Module -Name AWS.Tools.S3 -ErrorAction Stop; return } catch {}
        try { Import-Module -Name AWSPowerShell.NetCore -ErrorAction Stop; return } catch {}
        throw "AWS Tools for PowerShell not found. Install with: Install-Module AWS.Tools.S3 -Scope CurrentUser"
    }
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
    if ($Region) {
        try { $cfg.RegionEndpoint = [Amazon.RegionEndpoint]::GetBySystemName($Region) } catch {}
    }
    $cfg.ForcePathStyle = [bool]$ForcePathStyle
    return (New-Object Amazon.S3.AmazonS3Client($creds, $cfg))
}

# Native S3 SigV4 (no AWS Tools) helpers
function Get-Bytes([string]$s) { return [System.Text.Encoding]::UTF8.GetBytes($s) }
function Get-HashHex([byte[]]$bytes) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        if ($null -eq $bytes) { $bytes = [byte[]]@() }
        $ms = [System.IO.MemoryStream]::new($bytes)
        try {
            $hashBytes = $sha.ComputeHash($ms)
            return ([BitConverter]::ToString($hashBytes)).Replace('-', '').ToLowerInvariant()
        } finally { $ms.Dispose() }
    } finally { $sha.Dispose() }
}
function Get-FileSha256Hex([string]$path) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $fs = [System.IO.File]::OpenRead($path)
    try { return ([BitConverter]::ToString($sha.ComputeHash($fs))).Replace('-', '').ToLowerInvariant() } finally { $fs.Close(); $sha.Dispose() }
}
function HmacSha256([byte[]]$key, [string]$data) {
    $h = [System.Security.Cryptography.HMACSHA256]::new($key)
    try {
        $dataBytes = Get-Bytes $data
        $ms = [System.IO.MemoryStream]::new($dataBytes)
        try { return $h.ComputeHash($ms) } finally { $ms.Dispose() }
    } finally { $h.Dispose() }
}
function GetSignatureKey([string]$secret, [string]$dateStamp, [string]$regionName, [string]$serviceName) {
    $kDate = HmacSha256 (Get-Bytes ('AWS4' + $secret)) $dateStamp
    $kRegion = HmacSha256 $kDate $regionName
    $kService = HmacSha256 $kRegion $serviceName
    return (HmacSha256 $kService 'aws4_request')
}
function UriEncode([string]$data, [bool]$encodeSlash) {
    if ($null -eq $data) { return '' }
    $enc = [System.Uri]::EscapeDataString($data)
    if (-not $encodeSlash) { $enc = $enc -replace '%2F','/' }
    return $enc
}
function BuildCanonicalPath([System.Uri]$uri) {
    $segments = $uri.AbsolutePath.Split('/')
    $encoded = @()
    foreach ($seg in $segments) { $encoded += (UriEncode $seg $false) }
    $path = ($encoded -join '/')
    if (-not $path.StartsWith('/')) { $path = '/' + $path }
    return $path
}
function ToHex([byte[]]$bytes) { return ([BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant() }
function BuildAuthHeaders($method, [System.Uri]$uri, [string]$region, [string]$accessKey, [string]$secretKey, [string]$payloadHash) {
    $algorithm = 'AWS4-HMAC-SHA256'
    $amzdate = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $datestamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd')
    $hostHeader = $uri.Host
    if (-not $uri.IsDefaultPort) { $hostHeader = "{0}:{1}" -f $hostHeader, $uri.Port }

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
    return @{ 'x-amz-date' = $amzdate; 'x-amz-content-sha256' = $payloadHash; 'Authorization' = $authHeader }
}
function BuildS3Uri([string]$endpointUrl, [string]$bucket, [string]$key, [bool]$forcePathStyle) {
    $base = [System.Uri]$endpointUrl
    $ub = [System.UriBuilder]::new($base)
    if ($forcePathStyle) {
        $p = ($ub.Path.TrimEnd('/'))
        if ([string]::IsNullOrEmpty($p)) { $p = '/' }
        $ub.Path = ($p.TrimEnd('/') + '/' + $bucket + '/' + $key)
    } else {
        $ub.Host = "$bucket." + $ub.Host
        $p = $ub.Path.TrimEnd('/')
        if ([string]::IsNullOrEmpty($p)) { $p = '/' }
        $ub.Path = ($p.TrimEnd('/') + '/' + $key)
    }
    return $ub.Uri
}
function Invoke-S3PutFile([string]$endpointUrl, [string]$bucket, [string]$key, [string]$filePath, [string]$region, [string]$ak, [string]$sk, [bool]$forcePathStyle) {
    $uri = BuildS3Uri -endpointUrl $endpointUrl -bucket $bucket -key $key -forcePathStyle $forcePathStyle
    $payloadHash = Get-FileSha256Hex -path $filePath
    Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue
    $client = [System.Net.Http.HttpClient]::new()
    try {
        $req = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Put, $uri)
        $stream = [System.IO.File]::OpenRead($filePath)
        $req.Content = [System.Net.Http.StreamContent]::new($stream)
        $hdrs = BuildAuthHeaders -method 'PUT' -uri $uri -region $region -accessKey $ak -secretKey $sk -payloadHash $payloadHash
        $req.Headers.TryAddWithoutValidation('x-amz-date', $hdrs['x-amz-date']) | Out-Null
        $req.Headers.TryAddWithoutValidation('Authorization', $hdrs['Authorization']) | Out-Null
        $req.Headers.TryAddWithoutValidation('x-amz-content-sha256', $hdrs['x-amz-content-sha256']) | Out-Null
        $resp = $client.SendAsync($req).Result
        if (-not $resp.IsSuccessStatusCode) { throw "S3 PUT failed: $([int]$resp.StatusCode) $($resp.ReasonPhrase)" }
    } finally { if ($req) { $req.Dispose() }; if ($stream) { $stream.Close(); $stream.Dispose() }; $client.Dispose() }
}
function Invoke-S3GetToFile([string]$endpointUrl, [string]$bucket, [string]$key, [string]$targetPath, [string]$region, [string]$ak, [string]$sk, [bool]$forcePathStyle) {
    $uri = BuildS3Uri -endpointUrl $endpointUrl -bucket $bucket -key $key -forcePathStyle $forcePathStyle
    $payloadHash = (Get-HashHex (Get-Bytes ''))
    Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue
    $client = [System.Net.Http.HttpClient]::new()
    try {
        $req = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Get, $uri)
        $hdrs = BuildAuthHeaders -method 'GET' -uri $uri -region $region -accessKey $ak -secretKey $sk -payloadHash $payloadHash
        $req.Headers.TryAddWithoutValidation('x-amz-date', $hdrs['x-amz-date']) | Out-Null
        $req.Headers.TryAddWithoutValidation('Authorization', $hdrs['Authorization']) | Out-Null
        $req.Headers.TryAddWithoutValidation('x-amz-content-sha256', $hdrs['x-amz-content-sha256']) | Out-Null
        $resp = $client.SendAsync($req).Result
        if (-not $resp.IsSuccessStatusCode) { throw "S3 GET failed: $([int]$resp.StatusCode) $($resp.ReasonPhrase)" }
        $bytes = $resp.Content.ReadAsByteArrayAsync().Result
        [System.IO.File]::WriteAllBytes($targetPath, $bytes)
    } finally { if ($req) { $req.Dispose() }; $client.Dispose() }
}

# Retrieve the passphrase from a user environment variable
$passphrase = [System.Environment]::GetEnvironmentVariable("ELYSIUM_PASSPHRASE", [System.EnvironmentVariableTarget]::User)
if ([string]::IsNullOrWhiteSpace($passphrase)) { Write-Error 'Passphrase not found in ELYSIUM_PASSPHRASE environment variable.'; exit }

# Timestamp
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

function Protect-FileWithAES {
    param (
        [Parameter(Mandatory = $true)]
        [string]$InputFile,

        [Parameter(Mandatory = $true)]
        [string]$OutputFile,

        [Parameter(Mandatory = $true)]
        [string]$Passphrase
    )

    # Derive key with PBKDF2 (HMACSHA256) + random salt
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $salt = New-Object byte[] 16
    $rng.GetBytes($salt)

    $kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Passphrase, $salt, 100000, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $key = $kdf.GetBytes(32)

    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize = 256
    $aes.BlockSize = 128
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.GenerateIV()

    $iv = $aes.IV
    $encryptor = $aes.CreateEncryptor($key, $iv)

    $fileStream = [System.IO.File]::Open($InputFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
    $outFileStream = [System.IO.File]::Create($OutputFile)

    try {
        # File header: magic 'ELY1' (4 bytes), salt (16 bytes), IV (16 bytes)
        $magic = [System.Text.Encoding]::ASCII.GetBytes('ELY1')
        $outFileStream.Write($magic, 0, $magic.Length)
        $outFileStream.Write($salt, 0, $salt.Length)
        $outFileStream.Write($iv, 0, $iv.Length)

        $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($outFileStream, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)
        try {
            $buffer = New-Object Byte[] 8192
            while (($read = $fileStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $cryptoStream.Write($buffer, 0, $read)
            }
        } finally {
            $cryptoStream.FlushFinalBlock()
            $cryptoStream.Close()
        }
    } finally {
        $outFileStream.Close(); $fileStream.Close(); $aes.Dispose(); $rng.Dispose(); $kdf.Dispose()
    }

    Write-Host "File has been encrypted (PBKDF2+AES-256-CBC): $OutputFile"
}
function Get-FileChecksum {
    param (
        [string]$Path,
        [string]$Algorithm = "SHA256"
    )
    $hasher = [System.Security.Cryptography.HashAlgorithm]::Create($Algorithm)
    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $hashBytes = $hasher.ComputeHash($stream)
        return [BitConverter]::ToString($hashBytes) -replace '-', ''
    }
    finally {
        $stream.Close()
        $hasher.Dispose()
    }
}

# Extract NTLM hashes
$reportBase = Normalize-ReportPath -p $ElysiumSettings['ReportPathBase']
if (-not (Test-Path $reportBase)) { New-Item -Path $reportBase -ItemType Directory -Force | Out-Null }

# Build domain details from settings (ordered to keep numeric index order)
$DomainDetails = [ordered]@{}
for ($i = 1; $ElysiumSettings.ContainsKey("Domain${i}Name"); $i++) {
    $DomainDetails["$i"] = @{
        Name = $ElysiumSettings["Domain${i}Name"]
        DC   = $ElysiumSettings["Domain${i}DC"]
        DA   = $ElysiumSettings["Domain${i}DA"]
    }
}

# User selects a domain
Write-Host "Select a domain to extract NTLM hashes:"
$DomainDetails.GetEnumerator() | Sort-Object { [int]$_.Key } | ForEach-Object { Write-Host "$($_.Key): $($_.Value.Name)" }
$selection = Read-Host "Enter the number of the domain"
$selectedDomain = $DomainDetails[$selection]

if (-not $selectedDomain) {
    Write-Error "Invalid selection."
    exit
}

# Update script variables based on selected domain
$domainController = $selectedDomain.DC
$credential = Get-Credential -Message "Enter AD credentials with replication rights for $($selectedDomain.Name)"

$domainPrefix = ($selectedDomain.Name -replace "\W", "_")
$baseName = "${domainPrefix}_NTLM_Hashes_$timestamp"
$exportPath = Join-Path -Path $scriptRoot -ChildPath "$baseName.txt"
$compressedFilePath = Join-Path -Path $scriptRoot -ChildPath "$baseName.zip"
$encryptedFilePath = Join-Path -Path $scriptRoot -ChildPath "$baseName.enc"
$blobName = "$baseName.enc"

$ntlmHashes = Get-ADReplAccount -All -Server $domainController -Credential $credential |
Where-Object { $_.NTHash } |
ForEach-Object { [BitConverter]::ToString($_.NTHash).Replace("-", "") } |
Sort-Object -Unique

$ntlmHashes | Out-File -FilePath $exportPath
Write-Host "NTLM hashes have been extracted to: $exportPath"

# Compress extracted NTLM hashes
Compress-Archive -Path $exportPath -DestinationPath $compressedFilePath
Write-Host "File has been compressed: $compressedFilePath"

# Encrypt the compressed file
Protect-FileWithAES -InputFile $compressedFilePath -OutputFile $encryptedFilePath -Passphrase $passphrase
Write-Host "File has been encrypted: $encryptedFilePath"

# Calculate the local file checksum
$localFileChecksum = Get-FileChecksum -Path $encryptedFilePath

if ($storageProvider -ieq 'S3') {
    # S3-compatible path (e.g., IDrive e2) without requiring AWS Tools
    if ([string]::IsNullOrWhiteSpace($s3BucketName)) { Write-Error 's3BucketName is missing in settings.'; exit }
    if ([string]::IsNullOrWhiteSpace($s3AccessKeyId) -or [string]::IsNullOrWhiteSpace($s3SecretAccessKey)) { Write-Error 's3AccessKeyId / s3SecretAccessKey missing in settings.'; exit }
    if ([string]::IsNullOrWhiteSpace($s3EndpointUrl)) { Write-Error 's3EndpointUrl is required for S3-compatible storage.'; exit }

    $usedAwsTools = $false
    if ($s3UseAwsTools) {
        try {
            $s3Client = New-S3Client -EndpointUrl $s3EndpointUrl -Region $s3Region -AccessKeyId $s3AccessKeyId -SecretAccessKey $s3SecretAccessKey -ForcePathStyle:$s3ForcePathStyle
            # Upload
            $putReq = New-Object Amazon.S3.Model.PutObjectRequest -Property @{ BucketName = $s3BucketName; Key = $blobName; FilePath = $encryptedFilePath }
            $null = $s3Client.PutObject($putReq)
            Write-Host "Encrypted file uploaded to S3-compatible bucket (AWS Tools): $blobName"
            $tempDownloadPath = [System.IO.Path]::GetTempFileName()
            $getReq = New-Object Amazon.S3.Model.GetObjectRequest -Property @{ BucketName = $s3BucketName; Key = $blobName }
            $getResp = $s3Client.GetObject($getReq)
            $getResp.WriteResponseStreamToFile($tempDownloadPath, $true)
            $getResp.Dispose()
            $downloadedFileChecksum = Get-FileChecksum -Path $tempDownloadPath
            $usedAwsTools = $true
        } catch {
            Write-Warning "AWS Tools path failed or not available. Falling back to native HTTP (SigV4). Details: $($_.Exception.Message)"
            $usedAwsTools = $false
        }
    }

    if (-not $usedAwsTools) {
        Invoke-S3PutFile -endpointUrl $s3EndpointUrl -bucket $s3BucketName -key $blobName -filePath $encryptedFilePath -region $s3Region -ak $s3AccessKeyId -sk $s3SecretAccessKey -forcePathStyle:$s3ForcePathStyle
        Write-Host "Encrypted file uploaded to S3-compatible bucket: $blobName"
        $tempDownloadPath = [System.IO.Path]::GetTempFileName()
        Invoke-S3GetToFile -endpointUrl $s3EndpointUrl -bucket $s3BucketName -key $blobName -targetPath $tempDownloadPath -region $s3Region -ak $s3AccessKeyId -sk $s3SecretAccessKey -forcePathStyle:$s3ForcePathStyle
        $downloadedFileChecksum = Get-FileChecksum -Path $tempDownloadPath
    }
}
else {
    # Azure Blob Storage path (default)
    $sas = $sasToken
    if ([string]::IsNullOrWhiteSpace($sas)) { Write-Error 'sasToken is missing in settings.'; exit }
    $sas = $sas.Trim(); if (-not $sas.StartsWith('?')) { $sas = '?' + $sas }
    try { Import-Module Az.Storage -ErrorAction Stop } catch {}
    $storageContext = New-AzStorageContext -StorageAccountName $storageAccountName -SasToken $sas

    # Ensure container exists
    $container = Get-AzStorageContainer -Name $containerName -Context $storageContext -ErrorAction SilentlyContinue
    if (-not $container) { Write-Error "Azure container '$containerName' not found or access denied."; exit }

    # Upload the encrypted file to Azure Blob Storage
    Set-AzStorageBlobContent -File $encryptedFilePath -Container $containerName -Blob $blobName -Context $storageContext | Out-Null
    Write-Host "Encrypted file uploaded to Azure Blob Storage: $blobName"

    # Download the blob to a temporary location to verify
    $tempDownloadPath = [System.IO.Path]::GetTempFileName()
    Get-AzStorageBlobContent -Blob $blobName -Container $containerName -Context $storageContext -Destination $tempDownloadPath -Force | Out-Null

    # Calculate the downloaded file checksum
    $downloadedFileChecksum = Get-FileChecksum -Path $tempDownloadPath
}

# Compare the checksums
if ($localFileChecksum -eq $downloadedFileChecksum) {
    Write-Host "The file was correctly uploaded. Checksum verified."
    # Clean up local and temporary files only on success
    Remove-Item -Path $exportPath, $compressedFilePath, $encryptedFilePath, $tempDownloadPath -Force
    if ($storageProvider -ieq 'S3') {
        Write-Host "Local and temporary files cleaned up after uploading to S3-compatible storage."
    } else {
        Write-Host "Local and temporary files cleaned up after uploading to Azure Blob Storage."
    }
}
else {
    Write-Warning "Checksum verification failed. Keeping local artifacts for investigation: $exportPath, $compressedFilePath, $encryptedFilePath"
    if (Test-Path $tempDownloadPath) { Remove-Item -Path $tempDownloadPath -Force }
}

    Write-Host "Script execution completed."
} finally {
    Stop-ExtractTranscript
}
