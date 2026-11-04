function Send-ElysiumHashExport {
    <#
    .SYNOPSIS
    Extracts current NT hashes (no usernames) from AD, encrypts them and uploads them to the provider.

    .DESCRIPTION
    Prompts for a domain from ElysiumSettings.txt and for credentials with replication rights,
    replicates accounts with Get-ADReplAccount, and writes the unique NT hashes of accounts that have
    one to a temp directory readable only by the current user. The list is zipped, encrypted with the
    stored passphrase (format ELY2), uploaded to the configured Azure Blob or S3-compatible storage, and
    verified by downloading it back and comparing SHA-256. Plaintext and archive are always deleted.
    #>
    [CmdletBinding()]
    param()

    Start-ElysiumTranscript -BasePath $InstallRoot -Name 'extract-hashes'
    try {
        Write-Host "Loading settings..."
        $ElysiumSettings = Read-ElysiumSettings -ScriptRoot $InstallRoot

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

        $DomainDetails = Get-DomainDetailsFromSettings -Settings $ElysiumSettings

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

            $ntlmHashes | Out-File -FilePath $exportPath -Encoding utf8
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
    } finally {
        Stop-ElysiumTranscript
    }
}
