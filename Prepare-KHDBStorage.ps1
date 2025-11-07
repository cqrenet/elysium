##################################################
##   ____ ___  ____  _____   _   _ _____ _____  ##
##  / ___/ _ \|  _ \| ____| | \ | | ____|_   _| ##
## | |  | | | | |_) |  _|   |  \| |  _|   | |   ##
## | |__| |_| |  _ <| |___ _| |\  | |___  | |   ##
##  \____\__\_\_| \_\_____(_)_| \_|_____| |_|   ##
##################################################
## Project: Elysium                             ##
## File: Prepare-KHDBStorage.ps1                ##
## Version: 1.0.0                               ##
## Support: support@cqre.net                    ##
##################################################

<#
.SYNOPSIS
Prepares sharded KHDB content for remote storage.

.DESCRIPTION
Splits a monolithic khdb.txt into two-hex prefix shards, generates a manifest
compatible with Update-KHDB.ps1, and optionally uploads both manifest and shards
to Azure Blob Storage or an S3-compatible bucket.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$SourcePath,

    [string]$OutputRoot,

    [ValidateRange(1, 8)]
    [int]$ShardSize = 2,

    [string]$ManifestVersion,

    [ValidateSet('None', 'Azure', 'S3')]
    [string]$StorageProvider = 'None',

    # Azure options
    [string]$StorageAccountName,
    [string]$ContainerName,
    [string]$SasToken,

    # S3-compatible options
    [string]$S3EndpointUrl,
    [string]$S3Region = 'us-east-1',
    [string]$S3BucketName,
    [string]$S3AccessKeyId,
    [string]$S3SecretAccessKey,
    [bool]$S3ForcePathStyle = $true,

    # Remote layout
    [string]$ManifestRemotePath = 'khdb/manifest.json',
    [string]$ShardRemotePrefix = 'khdb/shards',

    [switch]$SkipUpload,
    [switch]$UploadOnly,

    [switch]$ShowProgress,
    [int]$ProgressUpdateInterval = 100000,

    [switch]$ForcePlainText,

    [string]$CheckpointPath,
    [switch]$NoCheckpoint,

    [switch]$Force,

    [string]$SettingsPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue

function Ensure-Directory {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }
}

function Remove-DirectoryContents {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    Get-ChildItem -LiteralPath $Path -Force | ForEach-Object {
        Remove-Item -LiteralPath $_.FullName -Recurse -Force
    }
}

function Read-KeyValueSettingsFile {
    param([string]$Path)
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

function Get-SettingsValue {
    param(
        [hashtable]$Settings,
        [string]$Key
    )
    if (-not $Settings) { return $null }
    if ($Settings.ContainsKey($Key)) { return $Settings[$Key] }
    return $null
}

function Merge-ShardsToFile {
    param(
        [psobject]$Manifest,
        [string]$ShardsRoot,
        [string]$TargetPath
    )

    $encoding = New-Object System.Text.UTF8Encoding($false)
    $writer = New-Object System.IO.StreamWriter($TargetPath, $false, $encoding, 1048576)
    try {
        foreach ($entry in ($Manifest.shards | Sort-Object name)) {
            $relative = [string]$entry.name
            if ([string]::IsNullOrWhiteSpace($relative)) { continue }
            $shardPath = Join-Path -Path $ShardsRoot -ChildPath $relative
            if (-not (Test-Path -LiteralPath $shardPath)) {
                throw "Missing shard on disk: $relative"
            }
            $reader = New-Object System.IO.StreamReader($shardPath, [System.Text.Encoding]::UTF8, $true, 1048576)
            try {
                while (($line = $reader.ReadLine()) -ne $null) {
                    $trimmed = $line.Trim()
                    if ($trimmed.Length -gt 0) { $writer.WriteLine($trimmed) }
                }
            } finally {
                $reader.Dispose()
            }
        }
    } finally {
        $writer.Dispose()
    }
}

function Get-NormalizedForwardPath {
    param([string]$PathValue)
    if ([string]::IsNullOrWhiteSpace($PathValue)) { return '' }
    return $PathValue.Replace('\', '/').Trim('/')
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
    $builder = [System.UriBuilder]::new("https://$Account.blob.core.windows.net/$Container/$normalizedBlob")
    $builder.Query = $sas.TrimStart('?')
    return $builder.Uri.AbsoluteUri
}

function Upload-AzureBlob {
    param(
        [string]$Account,
        [string]$Container,
        [string]$Sas,
        [string]$BlobName,
        [string]$FilePath,
        [string]$ContentType
    )

    $uri = Build-BlobUri -Account $Account -Container $Container -Sas $Sas -BlobName $BlobName
    $request = $null
    $stream = $null
    $client = [System.Net.Http.HttpClient]::new()
    try {
        $request = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Put, $uri)
        $stream = [System.IO.File]::OpenRead($FilePath)
        $content = New-Object System.Net.Http.StreamContent($stream)
        if ([string]::IsNullOrWhiteSpace($ContentType)) {
            $ContentType = 'application/octet-stream'
        }
        $content.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse($ContentType)
        $request.Content = $content
        $request.Headers.TryAddWithoutValidation('x-ms-blob-type', 'BlockBlob') | Out-Null
        $request.Headers.TryAddWithoutValidation('x-ms-version', '2020-10-02') | Out-Null

        $response = $client.SendAsync($request).GetAwaiter().GetResult()
        $null = $response.EnsureSuccessStatusCode()
    } finally {
        if ($stream) { $stream.Dispose() }
        if ($request) { $request.Dispose() }
        if ($client) { $client.Dispose() }
    }
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

function Invoke-S3HttpUpload {
    param(
        [string]$EndpointUrl,
        [string]$Bucket,
        [string]$Key,
        [string]$FilePath,
        [string]$Region,
        [string]$AccessKeyId,
        [string]$SecretAccessKey,
        [bool]$ForcePathStyle,
        [string]$PayloadHash,
        [string]$ContentType
    )

    $uri = BuildS3Uri -endpointUrl $EndpointUrl -bucket $Bucket -key $Key -forcePathStyle $ForcePathStyle
    $headers = BuildAuthHeaders -method 'PUT' -uri $uri -region $Region -accessKey $AccessKeyId -secretKey $SecretAccessKey -payloadHash $PayloadHash

    $client = [System.Net.Http.HttpClient]::new()
    $request = $null
    $stream = $null
    try {
        $request = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Put, $uri)
        foreach ($kvp in $headers.GetEnumerator()) {
            $request.Headers.TryAddWithoutValidation($kvp.Key, $kvp.Value) | Out-Null
        }
        $stream = [System.IO.File]::OpenRead($FilePath)
        $content = New-Object System.Net.Http.StreamContent($stream)
        if ([string]::IsNullOrWhiteSpace($ContentType)) {
            $ContentType = 'application/octet-stream'
        }
        $content.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse($ContentType)
        $request.Content = $content

        $response = $client.SendAsync($request, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
        $null = $response.EnsureSuccessStatusCode()
    } finally {
        if ($stream) { $stream.Dispose() }
        if ($request) { $request.Dispose() }
        if ($client) { $client.Dispose() }
    }
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

function Split-KhdbIntoShards {
    param(
        [string]$Source,
        [string]$ShardRoot,
        [int]$PrefixLength,
        [string]$InvalidOutputPath,
        [switch]$ShowProgress,
        [int]$ProgressUpdateInterval = 100000,
        [string]$ProgressActivity = 'Splitting KHDB',
        [switch]$ForcePlainText,
        [switch]$EnableCheckpoint,
        [string]$CheckpointPath,
        [switch]$Resume,
        [psobject]$ResumeState
    )

    $hashRegex = '^[0-9A-Fa-f]{32}$'
    $encoding = New-Object System.Text.UTF8Encoding($false)
    $ShardRoot = [System.IO.Path]::GetFullPath($ShardRoot)
    Ensure-Directory $ShardRoot

    if ($Resume -and -not $EnableCheckpoint) { throw 'Resume requested without a checkpoint.' }
    if ($EnableCheckpoint -and -not $ForcePlainText) { throw 'Checkpointing requires -ForcePlainText so the source is processed as plain text hashes.' }

    $shardStates = @{}
    $stats = @{}
    $total = 0L
    $resumeFilePosition = 0L

    $meta = @{
        TotalLines = 0L
        InvalidLines = 0L
        SkippedLines = 0L
        InvalidSamples = New-Object System.Collections.Generic.List[string]
    }

    if ($Resume -and $ResumeState) {
        if ($ResumeState.sourcePath -and ($ResumeState.sourcePath -ne $Source)) {
            throw "Checkpoint source '$($ResumeState.sourcePath)' does not match current source '$Source'."
        }
        if ($ResumeState.prefixLength -and ([int]$ResumeState.prefixLength -ne $PrefixLength)) {
            throw "Checkpoint prefix length $($ResumeState.prefixLength) does not match requested $PrefixLength."
        }
        if ($ResumeState.forcePlainText -ne $true) {
            throw 'Checkpoint was created without -ForcePlainText; resume is not supported in that mode.'
        }
        if ($ResumeState.shardRoot) {
            $resumeShardRoot = [System.IO.Path]::GetFullPath([string]$ResumeState.shardRoot)
            if ($resumeShardRoot -ne $ShardRoot) {
                throw "Checkpoint shard root '$resumeShardRoot' does not match target '$ShardRoot'."
            }
        }
        if ($ResumeState.totalLines) { $meta.TotalLines = [long]$ResumeState.totalLines }
        if ($ResumeState.invalidLines) { $meta.InvalidLines = [long]$ResumeState.invalidLines }
        if ($ResumeState.skippedLines) { $meta.SkippedLines = [long]$ResumeState.skippedLines }
        if ($ResumeState.validEntries) { $total = [long]$ResumeState.validEntries }
        if ($ResumeState.filePosition) { $resumeFilePosition = [long]$ResumeState.filePosition }
    }
    $plainReader = $null
    $plainBaseStream = $null

    # Pre-create all shard writers for the full prefix space (e.g., 256 for 2 hex digits)
    $prefixList = @()
    $prefixChars = '0123456789abcdef'
    function Get-AllPrefixes([int]$length) {
        if ($length -le 0) { return @('') }
        $subs = Get-AllPrefixes ($length - 1)
        $result = @()
        foreach ($c in $prefixChars.ToCharArray()) {
            foreach ($s in $subs) {
                $result += ($s + $c)
            }
        }
        return $result
    }
    $prefixList = Get-AllPrefixes $PrefixLength
    foreach ($prefix in $prefixList) {
        $shardPath = Join-Path -Path $ShardRoot -ChildPath ("$prefix.txt")
        Ensure-Directory (Split-Path -Path $shardPath -Parent)
        # Open with large buffer (1 MiB)
        $writer = New-Object System.IO.StreamWriter($shardPath, $false, $encoding, 1048576)
        $state = [ordered]@{
            Writer = $writer
            Path = $shardPath
            Count = 0
            PendingLine = $null
            PendingHash = $null
            PendingCount = -1
        }
        $shardStates[$prefix] = $state
    }

    $sourceItem = Get-Item -LiteralPath $Source -ErrorAction Stop
    if ($ForcePlainText -and $sourceItem.PSIsContainer) {
        throw 'ForcePlainText can only be used when SourcePath is a file. Provide a plain khdb.txt file, not a directory.'
    }
    if ($EnableCheckpoint -and $sourceItem.PSIsContainer) {
        throw 'Checkpointing/resume is only supported when SourcePath points to a plain hash file.'
    }
    $sourceBaseDir = if ($sourceItem.PSIsContainer) { $sourceItem.FullName } else { Split-Path -Parent $sourceItem.FullName }
    $currentSource = if ($sourceItem.PSIsContainer) { $sourceItem.FullName } else { $sourceItem.Name }

    $maxInvalidSamples = 10
    [System.IO.StreamWriter]$invalidWriter = $null
    $ensureInvalidWriter = {
        if (-not $InvalidOutputPath) { return }
        if (-not $invalidWriter) {
            $parent = Split-Path -Parent $InvalidOutputPath
            if ($parent) { Ensure-Directory $parent }
            $appendInvalid = $Resume -and (Test-Path -LiteralPath $InvalidOutputPath)
            $invalidWriter = New-Object System.IO.StreamWriter($InvalidOutputPath, $appendInvalid, $encoding, 1048576)
        }
    }

    if ($Resume -and $ResumeState -and $ResumeState.shardStates) {
        foreach ($resumeShard in $ResumeState.shardStates) {
            $prefix = [string]$resumeShard.prefix
            if ([string]::IsNullOrWhiteSpace($prefix)) { continue }
            $shardPath = Join-Path -Path $ShardRoot -ChildPath ("$prefix.txt")
            Ensure-Directory (Split-Path -Path $shardPath -Parent)
            $writer = New-Object System.IO.StreamWriter($shardPath, $true, $encoding, 1048576)
            $state = [ordered]@{
                Writer = $writer
                Path = $shardPath
                Count = if ($resumeShard.count -ne $null) { [long]$resumeShard.count } else { 0L }
                PendingLine = $resumeShard.pendingLine
                PendingHash = $resumeShard.pendingHash
                PendingCount = if ($resumeShard.pendingCount -ne $null) { [int]$resumeShard.pendingCount } else { -1 }
            }
            $shardStates[$prefix] = $state
        }
    }

    if ($ShowProgress) {
        if ($ProgressUpdateInterval -lt 1) { $ProgressUpdateInterval = 100000 }
    }
    $progressStopwatch = if ($ShowProgress) { [System.Diagnostics.Stopwatch]::StartNew() } else { $null }
    $checkpointEncoding = New-Object System.Text.UTF8Encoding($false)
    $saveCheckpoint = {
        param([long]$filePosition)
        if (-not $EnableCheckpoint) { return }
        foreach ($s in $shardStates.Values) { $s.Writer.Flush() }
        if ($invalidWriter) { $invalidWriter.Flush() }
        $payload = [ordered]@{
            version        = 1
            savedAt        = (Get-Date).ToUniversalTime().ToString('o')
            sourcePath     = $Source
            shardRoot      = $ShardRoot
            forcePlainText = [bool]$ForcePlainText
            prefixLength   = $PrefixLength
            mode           = 'Plain'
            filePosition   = $filePosition
            totalLines     = [long]$meta.TotalLines
            invalidLines   = [long]$meta.InvalidLines
            skippedLines   = [long]$meta.SkippedLines
            validEntries   = [long]$total
            shardStates    = @()
        }
        foreach ($entry in ($shardStates.GetEnumerator() | Sort-Object Key)) {
            $state = $entry.Value
            $payload.shardStates += [ordered]@{
                prefix       = $entry.Key
                count        = [long]$state.Count
                pendingLine  = $state.PendingLine
                pendingHash  = $state.PendingHash
                pendingCount = $state.PendingCount
            }
        }
        [System.IO.File]::WriteAllText($CheckpointPath, ($payload | ConvertTo-Json -Depth 6), $checkpointEncoding)
    }
    $invokeProgress = {
        param([bool]$Force = $false, [string]$Context)
        if (-not $ShowProgress) { return }
        if (-not $progressStopwatch) { return }
        $shouldUpdate = $Force
        if (-not $shouldUpdate) {
            if ($ProgressUpdateInterval -gt 0 -and $meta.TotalLines -gt 0 -and ($meta.TotalLines % $ProgressUpdateInterval) -eq 0) {
                $shouldUpdate = $true
            } elseif ($progressStopwatch.ElapsedMilliseconds -ge 1000) {
                $shouldUpdate = $true
            }
        }
        if (-not $shouldUpdate) { return }
        $statusContext = $Context
        if ([string]::IsNullOrWhiteSpace($statusContext)) {
            $statusContext = if ($currentSource) { Split-Path -Leaf $currentSource } else { 'input' }
        }
        $status = "Processed {0:N0} hashes (+{1:N0} invalid, {2:N0} skipped, {3:N0} lines) [{4}]" -f $total, $meta.InvalidLines, $meta.SkippedLines, $meta.TotalLines, $statusContext
        Write-Progress -Activity $ProgressActivity -Status $status -PercentComplete 0
        if ($EnableCheckpoint -and $plainReader) {
            $checkpointPosition = if ($plainBaseStream) { $plainBaseStream.Position } else { $plainReader.BaseStream.Position }
            & $saveCheckpoint $checkpointPosition
        }
        $progressStopwatch.Restart()
    }

    $processHashLine = {
        param(
            [string]$rawLine,
            [string]$prefix
        )
        if ($null -eq $rawLine) { return }
        $trimmed = $rawLine.Trim()
        if ($trimmed.Length -eq 0) { return }
        if ($trimmed.StartsWith('#')) { return }
        if ($ForcePlainText -and $trimmed -match '(?i)\.gz(\s*)$') {
            $meta.TotalLines++
            $meta.SkippedLines++
            return
        }

        # Fast path for valid 32-char hex lines
        if ($rawLine.Length -eq 32 -and $rawLine -match '^[0-9A-Fa-f]{32}$') {
            $prefixKey = $rawLine.Substring(0, $PrefixLength).ToLowerInvariant()
            $shardStates[$prefixKey].Writer.WriteLine($rawLine.ToUpperInvariant())
            $meta.TotalLines++
            $total++
            return
        }

        $meta.TotalLines++

        $parts = $trimmed.Split(':', 2)
        $hashPortion = $parts[0].Trim()
        if (-not [string]::IsNullOrWhiteSpace($prefix)) {
            $hashPortion = ($prefix.Trim() + $hashPortion)
        }
        if ($hashPortion.Length -ne 32 -or $hashPortion -notmatch $hashRegex) {
            $match = [regex]::Match($hashPortion, '[0-9A-Fa-f]{32}')
            if ($match.Success) {
                $hashPortion = $match.Value
            }
        }
        if ($hashPortion.Length -ne 32 -or $hashPortion -notmatch $hashRegex) {
            $meta.InvalidLines++
            if ($meta.InvalidSamples.Count -lt $maxInvalidSamples) {
                [void]$meta.InvalidSamples.Add($trimmed)
            }
            & $ensureInvalidWriter
            if ($invalidWriter) { $invalidWriter.WriteLine($trimmed) }
            & $invokeProgress $false
            return
        }
        if ($hashPortion.Length -lt $PrefixLength) {
            $meta.InvalidLines++
            if ($meta.InvalidSamples.Count -lt $maxInvalidSamples) {
                [void]$meta.InvalidSamples.Add($trimmed)
            }
            & $ensureInvalidWriter
            if ($invalidWriter) { $invalidWriter.WriteLine($trimmed) }
            & $invokeProgress $false
            return
        }
        $normalizedHash = $hashPortion.ToUpperInvariant()
        $countValue = 0
        if ($parts.Count -gt 1) {
            $countText = $parts[1].Trim()
            if (-not [string]::IsNullOrWhiteSpace($countText)) {
                $null = [int]::TryParse($countText, [ref]$countValue)
                if ($countValue -lt 0) { $countValue = 0 }
            }
        }
        $normalizedLine = if ($parts.Count -gt 1 -and -not [string]::IsNullOrWhiteSpace($parts[1])) {
            "{0}:{1}" -f $normalizedHash, $parts[1].Trim()
        } else {
            $normalizedHash
        }

        $prefixKey = $normalizedHash.Substring(0, $PrefixLength).ToLowerInvariant()
        if (-not $shardStates.ContainsKey($prefixKey)) {
            $shardPath = Join-Path -Path $ShardRoot -ChildPath ("$prefixKey.txt")
            Ensure-Directory (Split-Path -Path $shardPath -Parent)
            $appendExisting = $Resume -and (Test-Path -LiteralPath $shardPath)
            $existingCount = 0L
            if ($appendExisting) {
                try {
                    $countReader = [System.IO.File]::OpenText($shardPath)
                    try {
                        while ($null -ne $countReader.ReadLine()) { $existingCount++ }
                    } finally { $countReader.Dispose() }
                } catch { $existingCount = 0L }
            }
            $writer = New-Object System.IO.StreamWriter($shardPath, $appendExisting, $encoding, 1048576)
            $state = [ordered]@{
                Writer = $writer
                Path = $shardPath
                Count = $existingCount
                PendingLine = $null
                PendingHash = $null
                PendingCount = -1
            }
            $shardStates[$prefixKey] = $state
        }
        $state = $shardStates[$prefixKey]

        if ($state.PendingHash -and $state.PendingHash -eq $normalizedHash) {
            if ($countValue -gt $state.PendingCount) {
                $state.PendingLine = $normalizedLine
                $state.PendingCount = $countValue
            }
        } else {
            if ($state.PendingLine) {
                $state.Writer.WriteLine($state.PendingLine)
                $state.Count++
                $total++
            }
            $state.PendingLine = $normalizedLine
            $state.PendingHash = $normalizedHash
            $state.PendingCount = $countValue
        }
        & $invokeProgress $false
    }

    $resolveGzipPath = {
        param([string]$pathValue)
        if ([string]::IsNullOrWhiteSpace($pathValue)) { return $null }
        if (Test-Path -LiteralPath $pathValue) { return (Resolve-Path -LiteralPath $pathValue).ProviderPath }
        if ([System.IO.Path]::IsPathRooted($pathValue)) { throw "Gzip file not found: $pathValue" }
        $candidate = Join-Path -Path $sourceBaseDir -ChildPath $pathValue
        if (Test-Path -LiteralPath $candidate) { return (Resolve-Path -LiteralPath $candidate).ProviderPath }
        $meta.TotalLines++
        $meta.InvalidLines++
        if ($meta.InvalidSamples.Count -lt $maxInvalidSamples) {
            [void]$meta.InvalidSamples.Add($pathValue)
        }
        & $ensureInvalidWriter
        if ($invalidWriter) { $invalidWriter.WriteLine($pathValue) }
        & $invokeProgress $true
        return $null
    }

    $processGzipFile = {
        param([string]$gzipPath)
        if ($ForcePlainText) {
            return
        }
        $resolved = & $resolveGzipPath $gzipPath
        if (-not $resolved) { return }
        if ($ShowProgress) { $currentSource = $gzipPath }
        $filePrefix = [System.IO.Path]::GetFileNameWithoutExtension($resolved)
        $fileStream = $null
        $gzipStream = $null
        $reader = $null
        try {
            $fileStream = [System.IO.File]::OpenRead($resolved)
            $gzipStream = New-Object System.IO.Compression.GZipStream($fileStream, [System.IO.Compression.CompressionMode]::Decompress)
            # Wrap in BufferedStream for larger read chunks
            $bufferedStream = New-Object System.IO.BufferedStream($gzipStream, 1048576)
            $reader = New-Object System.IO.StreamReader($bufferedStream, [System.Text.Encoding]::UTF8, $true, 1048576)
            while (($line = $reader.ReadLine()) -ne $null) {
                & $processHashLine $line $filePrefix
            }
        } finally {
            if ($reader) { $reader.Dispose() }
            if ($gzipStream) { $gzipStream.Dispose() }
            if ($fileStream) { $fileStream.Dispose() }
        }
        & $invokeProgress $true $gzipPath
    }

    try {
        if ($sourceItem.PSIsContainer) {
            $gzipFiles = Get-ChildItem -LiteralPath $sourceItem.FullName -Filter '*.gz' -File -Recurse | Sort-Object FullName
            if (-not $gzipFiles) { throw "Source directory '$($sourceItem.FullName)' does not contain any .gz files." }
            foreach ($file in $gzipFiles) {
                & $processGzipFile $file.FullName
            }
        } else {
            if ($ShowProgress) { $currentSource = $sourceItem.FullName }
            $mode = if ($ForcePlainText) { 'Plain' } else { $null }
            # Use BufferedStream for larger read chunks
            $fileStream = [System.IO.File]::Open($sourceItem.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
            if ($Resume -and $resumeFilePosition -gt 0) {
                if ($fileStream.Length -lt $resumeFilePosition) {
                    throw "Checkpoint position $resumeFilePosition exceeds source length $($fileStream.Length)."
                }
                $fileStream.Seek($resumeFilePosition, [System.IO.SeekOrigin]::Begin) | Out-Null
            }
            $bufferedStream = New-Object System.IO.BufferedStream($fileStream, 1048576)
            $reader = New-Object System.IO.StreamReader($bufferedStream, [System.Text.Encoding]::UTF8, $true, 1048576)
            $plainReader = $reader
            $plainBaseStream = $fileStream
            try {
                while (($line = $reader.ReadLine()) -ne $null) {
                    $trimmed = $line.Trim()
                    if ($trimmed.Length -eq 0) { continue }
                    if ($trimmed.StartsWith('#')) { continue }
                    if (-not $mode) {
                        if ($trimmed -like '*.gz') {
                            $resolvedProbe = & $resolveGzipPath $trimmed
                            if ($resolvedProbe) {
                                $mode = 'GzList'
                                if ($ShowProgress) { $currentSource = $trimmed }
                            } else {
                                continue
                            }
                        } else {
                            $mode = 'Plain'
                        }
                    }

                    if ($mode -eq 'Plain') {
                        & $processHashLine $line $null
                    } elseif (-not $ForcePlainText -and $trimmed -like '*.gz') {
                        & $processGzipFile $trimmed
                    } else {
                        if ($ForcePlainText -and $trimmed -match '(?i)\.gz(\s*)$') {
                            $meta.TotalLines++
                            $meta.SkippedLines++
                        } else {
                            $meta.TotalLines++
                            $meta.InvalidLines++
                            if ($meta.InvalidSamples.Count -lt $maxInvalidSamples) {
                                [void]$meta.InvalidSamples.Add($trimmed)
                            }
                            & $ensureInvalidWriter
                            if ($invalidWriter) { $invalidWriter.WriteLine($trimmed) }
                        }
                        & $invokeProgress $false
                    }
                }
            } finally {
                if ($reader) { $reader.Dispose() }
                if ($fileStream) { $fileStream.Dispose() }
                $plainReader = $null
                $plainBaseStream = $null
            }
        }
    } finally {
        if ($invalidWriter) { $invalidWriter.Dispose() }
    }

    foreach ($entry in ($shardStates.GetEnumerator() | Sort-Object Key)) {
        $prefix = $entry.Key
        $state = $entry.Value
        if ($state.PendingLine) {
            $state.Writer.WriteLine($state.PendingLine)
            $state.Count++
            $total++
            $state.PendingLine = $null
        }
        $state.Writer.Dispose()
        $stats[$prefix] = [ordered]@{
            Path = $state.Path
            Count = $state.Count
        }
    }

    if ($total -eq 0) { throw 'Source did not contain any valid hashes after processing.' }
    if ($ShowProgress) {
        $status = "Processed {0:N0} hashes (+{1:N0} invalid, {2:N0} skipped, {3:N0} lines)" -f $total, $meta.InvalidLines, $meta.SkippedLines, $meta.TotalLines
        Write-Progress -Activity $ProgressActivity -Status $status -Completed
    }
    return [pscustomobject]@{
        TotalEntries = [long]$total
        ShardStats   = $stats
        TotalLines   = [long]$meta.TotalLines
        InvalidLines = [long]$meta.InvalidLines
        SkippedLines = [long]$meta.SkippedLines
        InvalidSamples = $meta.InvalidSamples.ToArray()
        InvalidOutputPath = if ($meta.InvalidLines -gt 0 -and $InvalidOutputPath) { $InvalidOutputPath } else { $null }
    }
}

function Write-JsonFile {
    param(
        [string]$Path,
        [object]$Data
    )

    $json = $Data | ConvertTo-Json -Depth 6
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $json, $encoding)
}

$resolvedSettingsPath = $null
$elysiumSettings = $null
if ($SettingsPath) {
    if (-not (Test-Path -LiteralPath $SettingsPath)) {
        throw "Settings file not found at $SettingsPath"
    }
    $resolvedSettingsPath = (Resolve-Path -LiteralPath $SettingsPath).Path
} else {
    $defaultSettingsCandidate = Join-Path -Path $PSScriptRoot -ChildPath 'ElysiumSettings.txt'
    if (Test-Path -LiteralPath $defaultSettingsCandidate) {
        $resolvedSettingsPath = (Resolve-Path -LiteralPath $defaultSettingsCandidate).Path
    }
}
if ($resolvedSettingsPath) {
    try {
        $elysiumSettings = Read-KeyValueSettingsFile -Path $resolvedSettingsPath
    } catch {
        throw "Failed to parse settings file '$resolvedSettingsPath': $($_.Exception.Message)"
    }
}

# Apply defaults from settings when caller did not specify overrides
if ($elysiumSettings) {
    if (-not $PSBoundParameters.ContainsKey('StorageProvider')) {
        $providerFromSettings = Get-SettingsValue -Settings $elysiumSettings -Key 'StorageProvider'
        if ($providerFromSettings) { $StorageProvider = $providerFromSettings }
    }
    if (-not $PSBoundParameters.ContainsKey('ManifestVersion')) {
        $manifestFromSettings = Get-SettingsValue -Settings $elysiumSettings -Key 'ManifestVersion'
        if ($manifestFromSettings) { $ManifestVersion = $manifestFromSettings }
    }

    $providerUpper = if ($StorageProvider) { $StorageProvider.ToUpperInvariant() } else { 'NONE' }
    if ($providerUpper -eq 'AZURE') {
        if (-not $PSBoundParameters.ContainsKey('StorageAccountName')) {
            $storageAccountSetting = Get-SettingsValue -Settings $elysiumSettings -Key 'storageAccountName'
            if ($storageAccountSetting) { $StorageAccountName = $storageAccountSetting }
        }
        if (-not $PSBoundParameters.ContainsKey('ContainerName')) {
            $containerSetting = Get-SettingsValue -Settings $elysiumSettings -Key 'containerName'
            if ($containerSetting) { $ContainerName = $containerSetting }
        }
        if (-not $PSBoundParameters.ContainsKey('SasToken')) {
            $sasSetting = Get-SettingsValue -Settings $elysiumSettings -Key 'sasToken'
            if ($sasSetting) { $SasToken = $sasSetting }
        }
    } elseif ($providerUpper -eq 'S3') {
        if (-not $PSBoundParameters.ContainsKey('S3EndpointUrl')) {
            $endpointSetting = Get-SettingsValue -Settings $elysiumSettings -Key 's3EndpointUrl'
            if ($endpointSetting) { $S3EndpointUrl = $endpointSetting }
        }
        if (-not $PSBoundParameters.ContainsKey('S3BucketName')) {
            $bucketSetting = Get-SettingsValue -Settings $elysiumSettings -Key 's3BucketName'
            if ($bucketSetting) { $S3BucketName = $bucketSetting }
        }
        if (-not $PSBoundParameters.ContainsKey('S3AccessKeyId')) {
            $accessKeySetting = Get-SettingsValue -Settings $elysiumSettings -Key 's3AccessKeyId'
            if ($accessKeySetting) { $S3AccessKeyId = $accessKeySetting }
        }
        if (-not $PSBoundParameters.ContainsKey('S3SecretAccessKey')) {
            $secretKeySetting = Get-SettingsValue -Settings $elysiumSettings -Key 's3SecretAccessKey'
            if ($secretKeySetting) { $S3SecretAccessKey = $secretKeySetting }
        }
        if (-not $PSBoundParameters.ContainsKey('S3Region')) {
            $regionSetting = Get-SettingsValue -Settings $elysiumSettings -Key 's3Region'
            if ($regionSetting) { $S3Region = $regionSetting }
        }
        if (-not $PSBoundParameters.ContainsKey('S3ForcePathStyle')) {
            $forcePathStyleSetting = Get-SettingsValue -Settings $elysiumSettings -Key 's3ForcePathStyle'
            if ($forcePathStyleSetting) {
                try { $S3ForcePathStyle = [System.Convert]::ToBoolean($forcePathStyleSetting) } catch {}
            }
        }
    }
}

# -- Argument validation ------------------------------------------------------

$resolvedSource = $null
if (-not $UploadOnly) {
    $resolvedSource = Resolve-Path -LiteralPath $SourcePath -ErrorAction Stop
    if (-not (Test-Path -LiteralPath $resolvedSource)) {
        throw "Source file not found at $SourcePath"
    }
}

if ($UploadOnly -and $SkipUpload) {
    throw '-UploadOnly cannot be combined with -SkipUpload.'
}
if ($UploadOnly -and $StorageProvider -eq 'None') {
    throw "-UploadOnly requires StorageProvider Azure or S3 so there is an upload to perform."
}

if ($UploadOnly) {
    if (-not $OutputRoot) {
        throw '-OutputRoot must be specified when using -UploadOnly.'
    }
    $resolvedOutputRoot = Resolve-Path -LiteralPath $OutputRoot -ErrorAction Stop
    $OutputRoot = $resolvedOutputRoot.Path
} else {
    if (-not $OutputRoot) {
        $defaultRoot = Join-Path -Path (Split-Path -Parent $resolvedSource.Path) -ChildPath 'khdb-package'
        $OutputRoot = $defaultRoot
    }
}

$manifestObject = $null
$manifestShards = @()
$totalEntries = 0L
$totalLines = 0L
$invalidCount = 0L
$skippedCount = 0L
$totalSizeBytes = 0L
$summaryMessage = $null
$manifestHash = $null
$manifestPath = Join-Path -Path $OutputRoot -ChildPath 'manifest.json'
$localShardRoot = Join-Path -Path $OutputRoot -ChildPath 'shards'
$normalizedShardPrefix = $null

$checkpointEnabled = $false
$resume = $false
$resumeState = $null
$resolvedCheckpointPath = $null

if ($UploadOnly) {
    if (-not (Test-Path -LiteralPath $localShardRoot)) {
        throw "UploadOnly requested but shard directory '$localShardRoot' was not found."
    }
    if (-not (Test-Path -LiteralPath $manifestPath)) {
        throw "UploadOnly requested but manifest '$manifestPath' does not exist."
    }

    try {
        $manifestObject = (Get-Content -LiteralPath $manifestPath -Encoding UTF8 -Raw) | ConvertFrom-Json -Depth 6
    } catch {
        throw "Failed to parse manifest '$manifestPath': $($_.Exception.Message)"
    }
    if (-not $manifestObject) {
        throw "Manifest '$manifestPath' is empty or invalid."
    }
    if (-not $manifestObject.shards -or $manifestObject.shards.Count -eq 0) {
        throw "Manifest '$manifestPath' does not contain shard metadata."
    }

    $manifestHash = (Get-FileHash -Path $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()

    $manifestShards = @()
    $totalSizeBytes = 0L
    foreach ($entry in ($manifestObject.shards | Sort-Object name)) {
        $name = [string]$entry.name
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        $localPath = Join-Path -Path $localShardRoot -ChildPath $name
        if (-not (Test-Path -LiteralPath $localPath)) {
            throw "Shard file '$name' listed in manifest was not found under '$localShardRoot'."
        }
        $fileInfo = Get-Item -LiteralPath $localPath
        $totalSizeBytes += $fileInfo.Length
        $manifestShards += [pscustomobject]@{
            name    = $name
            prefix  = [string]$entry.prefix
            entries = if ($entry.entries -ne $null) { [long]$entry.entries } else { 0L }
            size    = [string]$fileInfo.Length
            sha256  = if ($entry.sha256) { [string]$entry.sha256.ToLowerInvariant() } else { '' }
        }
    }
    if ($manifestShards.Count -eq 0) {
        throw "Manifest '$manifestPath' did not produce any shard records to upload."
    }

    $totalEntries = if ($manifestObject.totalEntries) { [long]$manifestObject.totalEntries } else { 0L }
    $totalLines = if ($manifestObject.inputLines) { [long]$manifestObject.inputLines } else { 0L }
    $invalidCount = if ($manifestObject.invalidEntries) { [long]$manifestObject.invalidEntries } else { 0L }
    $skippedCount = if ($manifestObject.skippedEntries) { [long]$manifestObject.skippedEntries } else { 0L }

    $normalizedShardPrefix = Get-NormalizedForwardPath -PathValue $ShardRemotePrefix
    $manifestShardPrefix = Get-NormalizedForwardPath -PathValue $manifestObject.shardPrefix
    if ($manifestShardPrefix -and $normalizedShardPrefix -and $manifestShardPrefix -ne $normalizedShardPrefix) {
        Write-Warning ("ShardRemotePrefix '{0}' does not match manifest shardPrefix '{1}'; using manifest value." -f $normalizedShardPrefix, $manifestShardPrefix)
    }
    if ($manifestShardPrefix) {
        $normalizedShardPrefix = $manifestShardPrefix
    }

    Write-Host "UploadOnly requested; reusing existing artifacts under '$OutputRoot'."
    Write-Host ("Manifest SHA256: {0}" -f $manifestHash)

    $summaryMessage = ("Summary: {0} shards, {1} valid hashes, {2} invalid entries, {3} skipped, {4:N0} bytes." -f $manifestShards.Count, $totalEntries, $invalidCount, $skippedCount, $totalSizeBytes)
} else {
    if (-not $NoCheckpoint) {
        if (-not $ForcePlainText) {
            Write-Warning 'Checkpointing is only available with -ForcePlainText; continuing without checkpoints.'
        } else {
            if (-not $CheckpointPath) {
                $CheckpointPath = Join-Path -Path $OutputRoot -ChildPath 'khdb.checkpoint.json'
            }
            $resolvedCheckpointPath = [System.IO.Path]::GetFullPath($CheckpointPath)
            $checkpointDirectory = Split-Path -Path $resolvedCheckpointPath -Parent
            if ($checkpointDirectory -and -not (Test-Path -LiteralPath $checkpointDirectory)) {
                [System.IO.Directory]::CreateDirectory($checkpointDirectory) | Out-Null
            }
            if (Test-Path -LiteralPath $resolvedCheckpointPath) {
                try {
                    $resumeState = (Get-Content -LiteralPath $resolvedCheckpointPath -Encoding UTF8 -Raw) | ConvertFrom-Json -Depth 6
                } catch {
                    throw "Failed to parse checkpoint '$resolvedCheckpointPath': $($_.Exception.Message)"
                }
                if (-not $resumeState) { throw "Checkpoint '$resolvedCheckpointPath' is empty or invalid." }
                if ($resumeState.version -and $resumeState.version -ne 1) { throw "Unsupported checkpoint version $($resumeState.version)." }
                $resume = $true
            }
            $checkpointEnabled = $true
        }
    }

    if ($resume -and $resumeState -and $resumeState.sourcePath) {
        $resumeSourcePath = [System.IO.Path]::GetFullPath([string]$resumeState.sourcePath)
        if ($resumeSourcePath -ne $resolvedSource.Path) {
            throw "Checkpoint source '$resumeSourcePath' does not match current source '$($resolvedSource.Path)'."
        }
    }

    if (Test-Path -LiteralPath $OutputRoot) {
        $startingFresh = -not $resume
        if ($startingFresh) {
            if (-not $Force) {
                $existing = Get-ChildItem -LiteralPath $OutputRoot -Force | Select-Object -First 1
                if ($existing) {
                    throw "Output root '$OutputRoot' already exists and is not empty. Use -Force to overwrite."
                }
            } else {
                Remove-DirectoryContents -Path $OutputRoot
            }
        }
    } else {
        Ensure-Directory $OutputRoot
    }

    Ensure-Directory $localShardRoot

    $invalidReportPath = Join-Path -Path $OutputRoot -ChildPath 'invalid-hashes.txt'
    if (-not $resume -and (Test-Path -LiteralPath $invalidReportPath)) { Remove-Item -LiteralPath $invalidReportPath -Force }

    Write-Host "Splitting '$($resolvedSource.Path)' into shard prefix length $ShardSize..."
    $splitResult = Split-KhdbIntoShards -Source $resolvedSource.Path -ShardRoot $localShardRoot -PrefixLength $ShardSize -InvalidOutputPath $invalidReportPath -ShowProgress:$ShowProgress -ProgressUpdateInterval $ProgressUpdateInterval -ProgressActivity 'Preparing KHDB shards' -ForcePlainText:$ForcePlainText -EnableCheckpoint:$checkpointEnabled -CheckpointPath $resolvedCheckpointPath -Resume:$resume -ResumeState $resumeState
    $totalEntries = [long]$splitResult.TotalEntries
    $totalLines = [long]$splitResult.TotalLines
    $invalidCount = [long]$splitResult.InvalidLines
    $skippedCount = [long]$splitResult.SkippedLines
    Write-Host ("Input summary: {0} non-empty line(s) -> {1} valid hash(es), {2} invalid entr(y/ies), {3} skipped." -f $totalLines, $totalEntries, $invalidCount, $skippedCount)
    if ($invalidCount -gt 0) {
        if ($splitResult.InvalidOutputPath) {
            Write-Warning ("Invalid lines saved to {0}" -f $splitResult.InvalidOutputPath)
        }
        if ($splitResult.InvalidSamples -and $splitResult.InvalidSamples.Count -gt 0) {
            Write-Warning "Sample invalid lines:"
            foreach ($sample in $splitResult.InvalidSamples) {
                Write-Warning ("  {0}" -f $sample)
            }
        }
    } elseif (-not $resume -and (Test-Path -LiteralPath $invalidReportPath)) {
        Remove-Item -LiteralPath $invalidReportPath -Force
    }

    $manifestShards = @()
    $totalSizeBytes = 0L

    foreach ($prefix in ($splitResult.ShardStats.Keys | Sort-Object)) {
        $info = $splitResult.ShardStats[$prefix]
        $fileInfo = Get-Item -LiteralPath $info.Path
        $totalSizeBytes += $fileInfo.Length
        $hash = (Get-FileHash -Path $info.Path -Algorithm SHA256).Hash.ToLowerInvariant()
        $manifestShards += [pscustomobject]@{
            name    = "$prefix.txt"
            prefix  = $prefix
            entries = $info.Count
            size    = [string]$fileInfo.Length
            sha256  = $hash
        }
    }

    $manifestVersionValue = if ([string]::IsNullOrWhiteSpace($ManifestVersion)) {
        (Get-Date).ToString('yyyyMMdd-HHmmss')
    } else {
        $ManifestVersion
    }

    $normalizedShardPrefix = Get-NormalizedForwardPath -PathValue $ShardRemotePrefix
    $manifestObject = [ordered]@{
        version        = $manifestVersionValue
        generatedAt    = (Get-Date).ToUniversalTime().ToString('o')
        shardSize      = $ShardSize
        shardPrefix    = $normalizedShardPrefix
        totalEntries   = $totalEntries
        inputLines     = $totalLines
        invalidEntries = $invalidCount
        skippedEntries = $skippedCount
        totalShards    = $manifestShards.Count
        totalSize      = [string]$totalSizeBytes
        shards         = $manifestShards
    }

    Write-Host ("Writing manifest to {0}" -f $manifestPath)
    Write-JsonFile -Path $manifestPath -Data $manifestObject
    $manifestHash = (Get-FileHash -Path $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()

    Write-Host ("Manifest SHA256: {0}" -f $manifestHash)
    $cleanCombinedPath = Join-Path -Path $OutputRoot -ChildPath 'khdb-clean.txt'
    Write-Host ("Writing cleaned aggregate to {0}..." -f $cleanCombinedPath)
    Merge-ShardsToFile -Manifest $manifestObject -ShardsRoot $localShardRoot -TargetPath $cleanCombinedPath
    $cleanHash = (Get-FileHash -Path $cleanCombinedPath -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Host ("Clean KHDB SHA256: {0}" -f $cleanHash)
    $summaryMessage = ("Summary: {0} shards, {1} valid hashes, {2} invalid entries, {3} skipped, {4:N0} bytes." -f $manifestShards.Count, $totalEntries, $invalidCount, $skippedCount, $totalSizeBytes)
}

$normalizedManifestRemote = Get-NormalizedForwardPath -PathValue $ManifestRemotePath
if ([string]::IsNullOrEmpty($normalizedManifestRemote)) {
    throw 'ManifestRemotePath cannot be empty.'
}

if (-not $UploadOnly) {
    if ($SkipUpload) {
        Write-Host "SkipUpload requested; files ready under '$OutputRoot'."
        Write-Host $summaryMessage
        if ($checkpointEnabled -and $resolvedCheckpointPath -and (Test-Path -LiteralPath $resolvedCheckpointPath)) {
            Remove-Item -LiteralPath $resolvedCheckpointPath -Force
        }
        return
    }
}
elseif ($SkipUpload) {
    # Should never hit due to earlier validation, but guard defensively.
    return
}

switch ($StorageProvider.ToUpperInvariant()) {
    'AZURE' {
        if ([string]::IsNullOrWhiteSpace($StorageAccountName)) { throw 'storageAccountName is required for Azure uploads.' }
        if ([string]::IsNullOrWhiteSpace($ContainerName)) { throw 'containerName is required for Azure uploads.' }
        if ([string]::IsNullOrWhiteSpace($SasToken)) { throw 'sasToken is required for Azure uploads.' }

        Write-Host "Uploading shards to Azure Blob Storage container '$ContainerName'..."
        foreach ($entry in $manifestShards) {
            $localPath = Join-Path -Path $localShardRoot -ChildPath $entry.name
            $remoteKey = Combine-StoragePath -Prefix $normalizedShardPrefix -Name $entry.name
            Write-Host (" -> {0}" -f $remoteKey)
            Upload-AzureBlob -Account $StorageAccountName -Container $ContainerName -Sas $SasToken -BlobName $remoteKey -FilePath $localPath -ContentType 'text/plain'
        }

        Write-Host ("Uploading manifest to {0}" -f $normalizedManifestRemote)
        Upload-AzureBlob -Account $StorageAccountName -Container $ContainerName -Sas $SasToken -BlobName $normalizedManifestRemote -FilePath $manifestPath -ContentType 'application/json'
    }
    'S3' {
        if ([string]::IsNullOrWhiteSpace($S3EndpointUrl)) { throw 's3EndpointUrl is required for S3 uploads.' }
        if ([string]::IsNullOrWhiteSpace($S3BucketName)) { throw 's3BucketName is required for S3 uploads.' }
        if ([string]::IsNullOrWhiteSpace($S3AccessKeyId) -or [string]::IsNullOrWhiteSpace($S3SecretAccessKey)) {
            throw 's3AccessKeyId and s3SecretAccessKey are required for S3 uploads.'
        }

        Write-Host "Uploading shards to S3 bucket '$S3BucketName'..."
        foreach ($entry in $manifestShards) {
            $localPath = Join-Path -Path $localShardRoot -ChildPath $entry.name
            $remoteKey = Combine-StoragePath -Prefix $normalizedShardPrefix -Name $entry.name
            Write-Host (" -> {0}" -f $remoteKey)
            Invoke-S3HttpUpload -EndpointUrl $S3EndpointUrl -Bucket $S3BucketName -Key $remoteKey -FilePath $localPath -Region $S3Region -AccessKeyId $S3AccessKeyId -SecretAccessKey $S3SecretAccessKey -ForcePathStyle $S3ForcePathStyle -PayloadHash $entry.sha256 -ContentType 'text/plain'
        }

        Write-Host ("Uploading manifest to {0}" -f $normalizedManifestRemote)
        Invoke-S3HttpUpload -EndpointUrl $S3EndpointUrl -Bucket $S3BucketName -Key $normalizedManifestRemote -FilePath $manifestPath -Region $S3Region -AccessKeyId $S3AccessKeyId -SecretAccessKey $S3SecretAccessKey -ForcePathStyle $S3ForcePathStyle -PayloadHash $manifestHash -ContentType 'application/json'
    }
    default {
        Write-Host "StorageProvider set to 'None'; skipping upload. Files available under '$OutputRoot'."
    }
}

Write-Host "Upload completed successfully."
Write-Host $summaryMessage

if ($checkpointEnabled -and $resolvedCheckpointPath -and (Test-Path -LiteralPath $resolvedCheckpointPath)) {
    Remove-Item -LiteralPath $resolvedCheckpointPath -Force
}
