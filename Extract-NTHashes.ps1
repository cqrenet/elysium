##################################################
##   ____ ___  ____  _____   _   _ _____ _____  ##
##  / ___/ _ \|  _ \| ____| | \ | | ____|_   _| ##
## | |  | | | | |_) |  _|   |  \| |  _|   | |   ##
## | |__| |_| |  _ <| |___ _| |\  | |___  | |   ##
##  \____\__\_\_| \_\_____(_)_| \_|_____| |_|   ##
##################################################
## Project: Elysium                             ##
## File: Extract-NTLMHashes.ps1                 ##
## Version: 1.2.0                               ##
## Support: support@cqre.net                    ##
##################################################

<#
#Requires -Modules DSInternals, Az.Storage
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

# External settings
$storageAccountName = $ElysiumSettings['storageAccountName']
$containerName = $ElysiumSettings['containerName']
$sasToken = $ElysiumSettings['sasToken']

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

# Build domain details from settings
$DomainDetails = @{}
for ($i = 1; $ElysiumSettings.ContainsKey("Domain${i}Name"); $i++) {
    $DomainDetails["$i"] = @{
        Name = $ElysiumSettings["Domain${i}Name"]
        DC   = $ElysiumSettings["Domain${i}DC"]
        DA   = $ElysiumSettings["Domain${i}DA"]
    }
}

# User selects a domain
Write-Host "Select a domain to extract NTLM hashes:"
$DomainDetails.GetEnumerator() | ForEach-Object { Write-Host "$($_.Key): $($_.Value.Name)" }
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

# Create the context for Azure Blob Storage with SAS token
$sas = $sasToken
if ([string]::IsNullOrWhiteSpace($sas)) { Write-Error 'sasToken is missing in settings.'; exit }
$sas = $sas.Trim(); if (-not $sas.StartsWith('?')) { $sas = '?' + $sas }
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

# Compare the checksums
if ($localFileChecksum -eq $downloadedFileChecksum) {
    Write-Host "The file was correctly uploaded. Checksum verified."
    # Clean up local and temporary files only on success
    Remove-Item -Path $exportPath, $compressedFilePath, $encryptedFilePath, $tempDownloadPath -Force
    Write-Host "Local and temporary files cleaned up after uploading to Azure Blob Storage."
}
else {
    Write-Warning "Checksum verification failed. Keeping local artifacts for investigation: $exportPath, $compressedFilePath, $encryptedFilePath"
    if (Test-Path $tempDownloadPath) { Remove-Item -Path $tempDownloadPath -Force }
}

    Write-Host "Script execution completed."
} finally {
    Stop-ExtractTranscript
}
