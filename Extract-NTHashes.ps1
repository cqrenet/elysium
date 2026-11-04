##################################################
##   ____ ___  ____  _____   _   _ _____ _____  ##
##  / ___/ _ \|  _ \| ____| | \ | | ____|_   _| ##
## | |  | | | | |_) |  _|   |  \| |  _|   | |   ##
## | |__| |_| |  _ <| |___ _| |\  | |___  | |   ##
##  \____\__\_\_| \_\_____(_)_| \_|_____| |_|   ##
##################################################
## Project: Elysium                             ##
## File: Extract-NTHashes.ps1                   ##
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

# Ensure consistent UTF-8 output for files across PS5.1/PS7 (Out-File defaults to UTF-16LE on
# Desktop edition and UTF-8 on Core, so the plaintext hash export's encoding would otherwise
# depend purely on which PowerShell host happens to run it).
try {
    $PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'
    $OutputEncoding = New-Object System.Text.UTF8Encoding($false)
} catch { }

$scriptRoot = $PSScriptRoot

[string]$commonHelper = Join-Path -Path $PSScriptRoot -ChildPath 'Elysium.Common.ps1'
if (-not (Test-Path -LiteralPath $commonHelper)) { throw "Common helper not found at $commonHelper" }
. $commonHelper
Restart-WithWindowsPowerShellIfAvailable -BoundParameters $PSBoundParameters -UnboundArguments $MyInvocation.UnboundArguments

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

function Normalize-ReportPath([string]$p) {
    if ([string]::IsNullOrWhiteSpace($p)) { return (Join-Path -Path $scriptRoot -ChildPath 'Reports') }
    if ([System.IO.Path]::IsPathRooted($p)) { return $p }
    return (Join-Path -Path $scriptRoot -ChildPath $p)
}

function Get-FileSha256Hex([string]$path) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $fs = [System.IO.File]::OpenRead($path)
    try { return ([BitConverter]::ToString($sha.ComputeHash($fs))).Replace('-', '').ToLowerInvariant() } finally { $fs.Close(); $sha.Dispose() }
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

function Invoke-S3DeleteFile([string]$endpointUrl, [string]$bucket, [string]$key, [string]$region, [string]$ak, [string]$sk, [bool]$forcePathStyle) {
    $uri = BuildS3Uri -endpointUrl $endpointUrl -bucket $bucket -key $key -forcePathStyle $forcePathStyle
    $payloadHash = (Get-HashHex (Get-Bytes ''))
    Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue
    $client = [System.Net.Http.HttpClient]::new()
    try {
        $req = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Delete, $uri)
        $hdrs = BuildAuthHeaders -method 'DELETE' -uri $uri -region $region -accessKey $ak -secretKey $sk -payloadHash $payloadHash
        $req.Headers.TryAddWithoutValidation('x-amz-date', $hdrs['x-amz-date']) | Out-Null
        $req.Headers.TryAddWithoutValidation('Authorization', $hdrs['Authorization']) | Out-Null
        $req.Headers.TryAddWithoutValidation('x-amz-content-sha256', $hdrs['x-amz-content-sha256']) | Out-Null
        $resp = $client.SendAsync($req).Result
        # S3 DELETE is idempotent and returns 204 even if the key never existed; anything else is a real failure.
        if (-not $resp.IsSuccessStatusCode) { throw "S3 DELETE failed: $([int]$resp.StatusCode) $($resp.ReasonPhrase)" }
    } finally { if ($req) { $req.Dispose() }; $client.Dispose() }
}

function Protect-FileWithAES {
    param (
        [Parameter(Mandatory = $true)]
        [string]$InputFile,

        [Parameter(Mandatory = $true)]
        [string]$OutputFile,

        [Parameter(Mandatory = $true)]
        [string]$Passphrase
    )

    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $salt = New-Object byte[] 16
    $rng.GetBytes($salt)

    # Derive two independent keys from one PBKDF2 byte stream: the first 32 bytes for AES-256, the
    # next 32 for HMAC-SHA256 (Rfc2898DeriveBytes.GetBytes returns a continuous stream across
    # calls on the same instance, so these two ranges never overlap). CBC alone gives no integrity
    # check - tampered or corrupted ciphertext just decrypts to garbage (or throws an unhelpful
    # padding exception) instead of being detected. Encrypt-then-MAC over magic+salt+iv+ciphertext
    # (format 'ELY2') catches both. Older 'ELY1' files this script produced have no MAC.
    $kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Passphrase, $salt, 100000, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $aesKey = $kdf.GetBytes(32)
    $hmacKey = $kdf.GetBytes(32)

    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize = 256
    $aes.BlockSize = 128
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.GenerateIV()
    $iv = $aes.IV

    $encryptor = $aes.CreateEncryptor($aesKey, $iv)
    $hmac = [System.Security.Cryptography.HMACSHA256]::new($hmacKey)
    try {
        $plainBytes = [System.IO.File]::ReadAllBytes($InputFile)
        $cipherBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)

        $magic = [System.Text.Encoding]::ASCII.GetBytes('ELY2')
        $header = $magic + $salt + $iv
        $mac = $hmac.ComputeHash($header + $cipherBytes)

        [System.IO.File]::WriteAllBytes($OutputFile, ($header + $cipherBytes + $mac))
    } finally {
        $encryptor.Dispose(); $hmac.Dispose(); $aes.Dispose(); $rng.Dispose(); $kdf.Dispose()
    }

    Write-Host "File has been encrypted (PBKDF2+AES-256-CBC+HMAC-SHA256): $OutputFile"
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
    } finally {
        $stream.Close()
        $hasher.Dispose()
    }
}

Start-ExtractTranscript -BasePath $scriptRoot
try {
    Write-Host "Loading settings..."
    $ElysiumSettings = Read-ElysiumSettings -ScriptRoot $scriptRoot

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

    # Retrieve the DPAPI-protected passphrase from a user environment variable (see Elysium.ps1)
    $protectedPassphrase = [System.Environment]::GetEnvironmentVariable("ELYSIUM_PASSPHRASE", [System.EnvironmentVariableTarget]::User)
    if ([string]::IsNullOrWhiteSpace($protectedPassphrase)) { throw 'Passphrase not found in ELYSIUM_PASSPHRASE environment variable. Run Elysium.ps1 once to set it.' }
    try {
        $securePassphrase = ConvertTo-SecureString -String $protectedPassphrase -ErrorAction Stop
    } catch {
        throw "ELYSIUM_PASSPHRASE is not in the expected DPAPI-protected format (leftover from an older Elysium version?). Re-run Elysium.ps1 to re-enter it."
    }
    $passphrase = [System.Net.NetworkCredential]::new('', $securePassphrase).Password

    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

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
        throw "Invalid selection."
    }

    $domainController = $selectedDomain.DC

    # Validate credentials and replication permissions before attempting DCSync
    $hasADModule = $null -ne (Get-Module -Name ActiveDirectory -ErrorAction SilentlyContinue)
    if (-not $hasADModule) {
        try { Import-Module ActiveDirectory -ErrorAction Stop; $hasADModule = $true } catch {}
    }

    if ($hasADModule) {
        $credential = Get-ValidatedADCredential -DomainName $selectedDomain.Name -Server $domainController
        try {
            $domainInfo = Get-ADDomain -Server $domainController -Credential $credential -ErrorAction Stop
            Test-ReplicationPermissions -DomainDN $domainInfo.DistinguishedName `
                -Server $domainController -Credential $credential
        } catch {
            throw $_.Exception.Message
        }
    } else {
        Write-Warning "ActiveDirectory module not available; skipping credential pre-check and replication permission verification."
        $credential = Get-Credential -Message "Enter AD credentials with replication rights for $($selectedDomain.Name)"
        if ($null -eq $credential) { throw "Credential prompt was cancelled." }
    }

    $domainPrefix = ($selectedDomain.Name -replace "\W", "_")
    $baseName = "${domainPrefix}_NTLM_Hashes_$timestamp"
    $blobName = "$baseName.enc"

    # Use a temp directory for all sensitive intermediate files so they are
    # never written to the installation directory and are always cleaned up.
    $tmpDir = New-Item -ItemType Directory -Path ([System.IO.Path]::Combine(
        [System.IO.Path]::GetTempPath(), "elysium-extract-" + [System.Guid]::NewGuid())) -Force
    try {
        # Plaintext NTLM hashes land in this directory before AES protection is applied below.
        # Strip inherited ACEs (e.g. a broad "Users" grant on the parent Temp folder) so only the
        # current user can read it while the finally block's cleanup hasn't run yet.
        $dirAcl = $tmpDir.GetAccessControl()
        $dirAcl.SetAccessRuleProtection($true, $false)
        $currentUserRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            [System.Security.Principal.WindowsIdentity]::GetCurrent().User,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $dirAcl.AddAccessRule($currentUserRule)
        $tmpDir.SetAccessControl($dirAcl)
    } catch {
        Write-Warning "Could not restrict ACL on temporary directory '$($tmpDir.FullName)': $($_.Exception.Message)"
    }
    $exportPath         = Join-Path -Path $tmpDir.FullName -ChildPath "$baseName.txt"
    $compressedFilePath = Join-Path -Path $tmpDir.FullName -ChildPath "$baseName.zip"
    $encryptedFilePath  = Join-Path -Path $tmpDir.FullName -ChildPath "$baseName.enc"
    $tempDownloadPath   = $null

    try {
        $ntlmHashes = Get-ADReplAccount -All -Server $domainController -Credential $credential |
            Where-Object { $_.NTHash } |
            ForEach-Object { [BitConverter]::ToString($_.NTHash).Replace("-", "") } |
            Sort-Object -Unique

        $ntlmHashes | Out-File -FilePath $exportPath
        Write-Host "NTLM hashes have been extracted to temporary file."

        Compress-Archive -Path $exportPath -DestinationPath $compressedFilePath
        Write-Host "File has been compressed."

        Protect-FileWithAES -InputFile $compressedFilePath -OutputFile $encryptedFilePath -Passphrase $passphrase

        $localFileChecksum = Get-FileChecksum -Path $encryptedFilePath

        if ($storageProvider -ieq 'S3') {
            if ([string]::IsNullOrWhiteSpace($s3BucketName)) { throw 's3BucketName is missing in settings.' }
            if ([string]::IsNullOrWhiteSpace($s3AccessKeyId) -or [string]::IsNullOrWhiteSpace($s3SecretAccessKey)) { throw 's3AccessKeyId / s3SecretAccessKey missing in settings.' }
            if ([string]::IsNullOrWhiteSpace($s3EndpointUrl)) { throw 's3EndpointUrl is required for S3-compatible storage.' }

            $usedAwsTools = $false
            if ($s3UseAwsTools) {
                try {
                    $s3Client = New-S3Client -EndpointUrl $s3EndpointUrl -Region $s3Region -AccessKeyId $s3AccessKeyId -SecretAccessKey $s3SecretAccessKey -ForcePathStyle:$s3ForcePathStyle
                    $putReq = New-Object Amazon.S3.Model.PutObjectRequest -Property @{ BucketName = $s3BucketName; Key = $blobName; FilePath = $encryptedFilePath }
                    $null = $s3Client.PutObject($putReq)
                    Write-Host "Encrypted file uploaded to S3-compatible bucket (AWS Tools): $blobName"
                    $tempDownloadPath = [System.IO.Path]::GetTempFileName()
                    $getReq = New-Object Amazon.S3.Model.GetObjectRequest -Property @{ BucketName = $s3BucketName; Key = $blobName }
                    $getResp = $s3Client.GetObject($getReq)
                    $getResp.WriteResponseStreamToFile($tempDownloadPath, $true)
                    $getResp.Dispose()
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
            }
        } else {
            $sas = $sasToken
            if ([string]::IsNullOrWhiteSpace($sas)) { throw 'sasToken is missing in settings.' }
            $sas = $sas.Trim(); if (-not $sas.StartsWith('?')) { $sas = '?' + $sas }
            try { Import-Module Az.Storage -ErrorAction Stop } catch {}
            $storageContext = New-AzStorageContext -StorageAccountName $storageAccountName -SasToken $sas

            $container = Get-AzStorageContainer -Name $containerName -Context $storageContext -ErrorAction SilentlyContinue
            if (-not $container) { throw "Azure container '$containerName' not found or access denied." }

            Set-AzStorageBlobContent -File $encryptedFilePath -Container $containerName -Blob $blobName -Context $storageContext | Out-Null
            Write-Host "Encrypted file uploaded to Azure Blob Storage: $blobName"

            $tempDownloadPath = [System.IO.Path]::GetTempFileName()
            Get-AzStorageBlobContent -Blob $blobName -Container $containerName -Context $storageContext -Destination $tempDownloadPath -Force | Out-Null
        }

        $downloadedFileChecksum = Get-FileChecksum -Path $tempDownloadPath

        if ($localFileChecksum -eq $downloadedFileChecksum) {
            Write-Host "The file was correctly uploaded. Checksum verified."
            Remove-Item -Path $encryptedFilePath -Force
            Remove-Item -Path $tempDownloadPath -Force
            if ($storageProvider -ieq 'S3') {
                Write-Host "Upload to S3-compatible storage completed and verified."
            } else {
                Write-Host "Upload to Azure Blob Storage completed and verified."
            }
        } else {
            Write-Warning "Checksum verification failed. Encrypted file preserved for investigation: $encryptedFilePath"
            if ($tempDownloadPath -and (Test-Path $tempDownloadPath)) {
                Remove-Item -Path $tempDownloadPath -Force -ErrorAction SilentlyContinue
            }

            # A checksum mismatch means the blob already sitting in remote storage under $blobName
            # is corrupt/incomplete. Leaving it live under its normal name would let a downstream
            # consumer silently fetch bad data, so remove it rather than only warning locally.
            try {
                if ($storageProvider -ieq 'S3') {
                    if ($usedAwsTools -and $s3Client) {
                        $delReq = New-Object Amazon.S3.Model.DeleteObjectRequest -Property @{ BucketName = $s3BucketName; Key = $blobName }
                        $null = $s3Client.DeleteObject($delReq)
                    } else {
                        Invoke-S3DeleteFile -endpointUrl $s3EndpointUrl -bucket $s3BucketName -key $blobName -region $s3Region -ak $s3AccessKeyId -sk $s3SecretAccessKey -forcePathStyle:$s3ForcePathStyle
                    }
                } else {
                    Remove-AzStorageBlob -Blob $blobName -Container $containerName -Context $storageContext -Force -ErrorAction Stop
                }
                Write-Warning "Removed the mismatched blob '$blobName' from remote storage."
            } catch {
                Write-Warning "Could not remove the mismatched blob '$blobName' from remote storage - remove it manually: $($_.Exception.Message)"
            }
        }
    } finally {
        # Always delete plaintext hashes and compressed archive regardless of outcome.
        foreach ($f in @($exportPath, $compressedFilePath)) {
            if ($f -and (Test-Path $f)) {
                Remove-Item -Path $f -Force -ErrorAction SilentlyContinue
            }
        }
    }

    Write-Host "Script execution completed."
} finally {
    Stop-ExtractTranscript
}
