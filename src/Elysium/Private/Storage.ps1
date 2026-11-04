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

# ---------------------------------------------------------------------------
# HTTP download helpers (Azure SAS URI and native SigV4 S3), with retry
# ---------------------------------------------------------------------------

function New-HttpClient {
    Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue
    $client = [System.Net.Http.HttpClient]::new()
    $client.Timeout = [TimeSpan]::FromSeconds(600)
    $client.DefaultRequestHeaders.UserAgent.ParseAdd("Elysium/$ElysiumVersion (+Update-KHDB)")
    return $client
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
        $response = $null
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
        } finally {
            if ($response) { $response.Dispose() }
        }
    }
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
