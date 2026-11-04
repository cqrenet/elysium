# ---------------------------------------------------------------------------
# Azure Blob Storage URIs and storage paths
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

# ---------------------------------------------------------------------------
# Storage access: one HTTP path for Azure Blob (SAS URI) and S3-compatible (SigV4)
# ---------------------------------------------------------------------------

function Get-StorageConfig {
    param([Parameter(Mandatory)][hashtable]$Settings)

    if ($Settings['StorageProvider'] -ieq 'S3') {
        $config = @{
            Provider        = 'S3'
            EndpointUrl     = $Settings['s3EndpointUrl']
            Region          = if ([string]::IsNullOrWhiteSpace($Settings['s3Region'])) { 'us-east-1' } else { $Settings['s3Region'] }
            Bucket          = $Settings['s3BucketName']
            AccessKeyId     = $Settings['s3AccessKeyId']
            SecretAccessKey = $Settings['s3SecretAccessKey']
            ForcePathStyle  = Get-BooleanSetting -Value $Settings['s3ForcePathStyle'] -Default $true
        }
        if ([string]::IsNullOrWhiteSpace($config.Bucket)) { throw 's3BucketName is missing or empty.' }
        if ([string]::IsNullOrWhiteSpace($config.AccessKeyId) -or [string]::IsNullOrWhiteSpace($config.SecretAccessKey)) { throw 's3AccessKeyId / s3SecretAccessKey missing or empty.' }
        if ([string]::IsNullOrWhiteSpace($config.EndpointUrl)) { throw 's3EndpointUrl is required for S3-compatible storage.' }
        return $config
    }

    $config = @{ Provider = 'Azure'; Account = $Settings['storageAccountName']; Container = $Settings['containerName']; Sas = $Settings['sasToken'] }
    if ([string]::IsNullOrWhiteSpace($config.Account)) { throw 'storageAccountName is missing or empty.' }
    if ([string]::IsNullOrWhiteSpace($config.Container)) { throw 'containerName is missing or empty.' }
    if ([string]::IsNullOrWhiteSpace($config.Sas)) { throw 'sasToken is missing or empty.' }
    return $config
}

function New-StorageRequest {
    # A PUT body carries a digest the storage service checks before storing anything: Content-MD5 for
    # Azure, the SigV4-signed SHA-256 payload hash for S3. A corrupted upload is rejected, never stored.
    param(
        [Parameter(Mandatory)][hashtable]$Storage,
        [Parameter(Mandatory)][ValidateSet('GET', 'PUT')][string]$Method,
        [Parameter(Mandatory)][string]$Key,
        [byte[]]$Body
    )

    Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue
    $httpMethod = [System.Net.Http.HttpMethod]::new($Method)
    if ($Storage.Provider -eq 'S3') {
        $uri = BuildS3Uri -endpointUrl $Storage.EndpointUrl -bucket $Storage.Bucket -key $Key -forcePathStyle $Storage.ForcePathStyle
        $request = [System.Net.Http.HttpRequestMessage]::new($httpMethod, $uri)
        $headers = BuildAuthHeaders -method $Method -uri $uri -region $Storage.Region -accessKey $Storage.AccessKeyId -secretKey $Storage.SecretAccessKey -payloadHash (Get-HashHex $Body)
        foreach ($kvp in $headers.GetEnumerator()) { [void]$request.Headers.TryAddWithoutValidation($kvp.Key, $kvp.Value) }
        if ($Method -eq 'PUT') { $request.Content = [System.Net.Http.ByteArrayContent]::new($Body) }
        return $request
    }

    $uri = Build-BlobUri -Account $Storage.Account -Container $Storage.Container -Sas $Storage.Sas -BlobName $Key
    $request = [System.Net.Http.HttpRequestMessage]::new($httpMethod, $uri)
    if ($Method -eq 'PUT') {
        [void]$request.Headers.TryAddWithoutValidation('x-ms-blob-type', 'BlockBlob')
        [void]$request.Headers.TryAddWithoutValidation('x-ms-version', '2020-10-02')
        $request.Content = [System.Net.Http.ByteArrayContent]::new($Body)
        # ponytail: MD5 throws on FIPS-enforced Windows; Test-ElysiumPasswordQuality already refuses those
        # hosts. If FIPS hosts must upload to Azure, switch to the x-ms-content-crc64 header.
        $md5 = [System.Security.Cryptography.MD5]::Create()
        try { $request.Content.Headers.ContentMD5 = $md5.ComputeHash($Body) } finally { $md5.Dispose() }
    }
    return $request
}

function New-StorageHttpClient {
    Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue
    $client = [System.Net.Http.HttpClient]::new()
    $client.Timeout = [TimeSpan]::FromSeconds(600)
    $client.DefaultRequestHeaders.UserAgent.ParseAdd("Elysium/$ElysiumVersion")
    return $client
}

function Invoke-StorageDownload {
    # Streams one object to $TargetPath. Network errors and HTTP 408/429/5xx are retried (5 attempts,
    # 2-30 s backoff); any other HTTP status fails at once.
    param(
        [Parameter(Mandatory)][hashtable]$Storage,
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][string]$TargetPath
    )

    $client = New-StorageHttpClient
    try {
        $delay = 2
        for ($attempt = 1; ; $attempt++) {
            $request = New-StorageRequest -Storage $Storage -Method GET -Key $Key
            $response = $null
            $permanent = $false
            try {
                $response = $client.SendAsync($request, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
                $code = [int]$response.StatusCode
                if (-not $response.IsSuccessStatusCode) {
                    $permanent = $code -lt 500 -and $code -ne 408 -and $code -ne 429
                    throw "HTTP $code $($response.ReasonPhrase)"
                }
                $source = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
                $target = [System.IO.File]::Create($TargetPath)
                try { $source.CopyTo($target, 1048576) } finally { $target.Dispose(); $source.Dispose() }
                return
            } catch {
                if ($permanent -or $attempt -ge 5) { throw "Download of '$Key' failed: $($_.Exception.Message)" }
                Write-Warning ("Download of '{0}' failed (attempt {1}/5): {2}. Retrying in {3}s..." -f $Key, $attempt, $_.Exception.Message, $delay)
            } finally {
                if ($response) { $response.Dispose() }
                $request.Dispose()
            }
            Start-Sleep -Seconds $delay
            $delay = [Math]::Min($delay * 2, 30)
        }
    } finally {
        $client.Dispose()
    }
}

function Invoke-StorageUpload {
    # One PUT; the service verifies the body against the digest New-StorageRequest attaches, so the
    # caller needs write access only - nothing is read back.
    param(
        [Parameter(Mandatory)][hashtable]$Storage,
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][string]$Path
    )

    $client = New-StorageHttpClient
    $request = New-StorageRequest -Storage $Storage -Method PUT -Key $Key -Body ([System.IO.File]::ReadAllBytes($Path))
    try {
        $response = $client.SendAsync($request).GetAwaiter().GetResult()
        try {
            if (-not $response.IsSuccessStatusCode) {
                $detail = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                if ($detail.Length -gt 500) { $detail = $detail.Substring(0, 500) }
                throw ("Upload of '{0}' failed: HTTP {1} {2}. {3}" -f $Key, [int]$response.StatusCode, $response.ReasonPhrase, $detail)
            }
        } finally {
            $response.Dispose()
        }
    } finally {
        $request.Dispose()
        $client.Dispose()
    }
}

function Invoke-InModuleRunspace {
    # Calls the module function $FunctionName once per parameter set, at most $ThrottleLimit at a time,
    # each in a pooled runspace that imports this module normally. Same behavior on Windows PowerShell
    # 5.1 and PowerShell 7. Waits for every call, then throws if any failed.
    param(
        [Parameter(Mandatory)][string]$FunctionName,
        [Parameter(Mandatory)][hashtable[]]$ParameterSets,
        [ValidateRange(1, 64)][int]$ThrottleLimit = 5,
        [string]$Activity = 'Working'
    )

    $sessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $sessionState.ImportPSModule([string[]]@($ModuleManifestPath))
    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $ThrottleLimit, $sessionState, $Host)
    $pool.Open()
    $jobs = @()
    try {
        foreach ($parameters in $ParameterSets) {
            $shell = [System.Management.Automation.PowerShell]::Create()
            $shell.RunspacePool = $pool
            [void]$shell.AddScript('param($f, $p) & (Get-Module Elysium) { param($f, $p) & $f @p } $f $p').AddArgument($FunctionName).AddArgument($parameters)
            $jobs += [pscustomobject]@{ Shell = $shell; Handle = $shell.BeginInvoke() }
        }
        while ($true) {
            $done = @($jobs | Where-Object { $_.Handle.IsCompleted }).Count
            Write-Progress -Activity $Activity -Status ("{0}/{1}" -f $done, $jobs.Count) -PercentComplete ([int](100 * $done / [Math]::Max(1, $jobs.Count)))
            if ($done -eq $jobs.Count) { break }
            Start-Sleep -Milliseconds 200
        }
        Write-Progress -Activity $Activity -Completed
        $failures = foreach ($job in $jobs) {
            try {
                [void]$job.Shell.EndInvoke($job.Handle)
            } catch {
                $e = $_.Exception
                if ($e -is [System.Management.Automation.MethodInvocationException] -and $e.InnerException) { $e = $e.InnerException }
                $e.Message
            }
        }
    } finally {
        foreach ($job in $jobs) { $job.Shell.Dispose() }
        $pool.Dispose()
    }
    if ($failures) {
        throw ("{0} of {1} {2} call(s) failed. First: {3}" -f @($failures).Count, $jobs.Count, $FunctionName, @($failures)[0])
    }
}
