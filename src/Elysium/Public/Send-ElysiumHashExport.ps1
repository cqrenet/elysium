function Send-ElysiumHashExport {
    <#
    .SYNOPSIS
    Extracts current NT hashes (no usernames) from AD, encrypts them and uploads them to the provider.

    .DESCRIPTION
    Uses the domain from ElysiumSettings.txt named by -Domain (or prompts for one) and the credentials in
    -Credential (or prompts for credentials with replication rights),
    replicates accounts with Get-ADReplAccount, and writes the unique NT hashes of accounts that have
    one to a temp directory readable only by the current user. The list is zipped, encrypted with the
    stored passphrase (format ELY2) and uploaded in one PUT to the configured Azure Blob or S3-compatible
    storage, which verifies the body against the digest sent with it. Plaintext and archive are always
    deleted; the encrypted file is kept in the temp directory only if the upload fails.

    .PARAMETER Domain
    Name of a configured domain (DomainNName in ElysiumSettings.txt). Omit to choose interactively.

    .PARAMETER Credential
    Account with the replication rights. Omit to be prompted.
    #>
    [CmdletBinding()]
    param(
        [string]$Domain,
        [System.Management.Automation.PSCredential]$Credential
    )

    Start-ElysiumTranscript -BasePath $InstallRoot -Name 'extract-hashes'
    try {
        Write-Host "Loading settings..."
        $ElysiumSettings = Read-ElysiumSettings -ScriptRoot $InstallRoot

        # Validated now, so a storage misconfiguration fails before any hashes are replicated.
        $storage = Get-StorageConfig $ElysiumSettings

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

        $selectedDomain = Select-ElysiumDomain -DomainDetails $DomainDetails -Name $Domain -Purpose 'extract NTLM hashes'

        $domainController = $selectedDomain.DC

        # Validate credentials and replication permissions before attempting DCSync
        $hasADModule = $null -ne (Get-Module -Name ActiveDirectory -ErrorAction SilentlyContinue)
        if (-not $hasADModule) {
            try { Import-Module ActiveDirectory -ErrorAction Stop; $hasADModule = $true } catch {}
        }

        if ($hasADModule) {
            if (-not $Credential) { $Credential = Get-ValidatedADCredential -DomainName $selectedDomain.Name -Server $domainController }
            try {
                $domainInfo = Get-ADDomain -Server $domainController -Credential $credential -ErrorAction Stop
                Test-ReplicationPermissions -DomainDN $domainInfo.DistinguishedName `
                    -Server $domainController -Credential $credential
            } catch {
                throw $_.Exception.Message
            }
        } else {
            Write-Warning "ActiveDirectory module not available; skipping credential pre-check and replication permission verification."
            if (-not $Credential) {
                $Credential = Get-Credential -Message "Enter AD credentials with replication rights for $($selectedDomain.Name)"
                if ($null -eq $Credential) { throw "Credential prompt was cancelled." }
            }
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

            # The service checks the body against the digest sent with the PUT and rejects a mismatch, so
            # there is nothing to read back (and the credentials need no read access to uploads).
            Invoke-StorageUpload -Storage $storage -Key $blobName -Path $encryptedFilePath
            Write-Host ("Encrypted file uploaded to {0} storage as '{1}'; the service verified its checksum." -f $storage.Provider, $blobName)
            Remove-Item -Path $encryptedFilePath -Force
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
