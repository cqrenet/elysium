# ---------------------------------------------------------------------------
# Parallel execution helpers
# ---------------------------------------------------------------------------

function Get-FunctionDefinitionText {
    param([Parameter(Mandatory)][string]$Name)
    $cmd = Get-Command -Name $Name -CommandType Function -ErrorAction Stop
    return $cmd.ScriptBlock.Ast.Extent.Text
}

# ---------------------------------------------------------------------------
# Azure Blob Storage helpers
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# Storage path utilities
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# AWS SigV4 / S3 helpers
# ---------------------------------------------------------------------------

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
    if ($null -eq $data) { return '' }
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
        'x-amz-date'           = $amzDate
        'x-amz-content-sha256' = $payloadHash
        'Authorization'        = $authHeader
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
