##################################################
##   ____ ___  ____  _____   _   _ _____ _____  ##
##  / ___/ _ \|  _ \| ____| | \ | | ____|_   _| ##
## | |  | | | | |_) |  _|   |  \| |  _|   | |   ##
## | |__| |_| |  _ <| |___ _| |\  | |___  | |   ##
##  \____\__\_\_| \_\_____(_)_| \_|_____| |_|   ##
##################################################
## Project: Elysium                             ##
## File: Extract-NTLMHashes.ps1                 ##
## Version: 1.0.2                               ##
## Support: support@cqre.net                    ##
##################################################

<#
.SYNOPSIS
Script for extracting NTLM hashes from live AD for further analysis.

.DESCRIPTION
This script will connect to selected domain (defined in ElysiumSettings.txt) using account with AD replication privileges and extract NTLM hashes from all active accounts. It will then compress and encrypt the resulting file, uploads it to designated Azure Storage account, checks for validity and then deletes everything. The hashes are extracted without usernames to minimise the sensitivity of the operation. Encryption is done with AES and passphrase that was defined in environment variable during first run.
#>

# Import settings
Write-Host "Loading settings..."
$ElysiumSettings = @{}
$settingsPath = "ElysiumSettings.txt"

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

# Ensure DSInternals and Az.Storage are installed
$requiredModules = @('DSInternals', 'Az.Storage')
foreach ($module in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Host "Installing $module module..."
        Install-Module $module -Scope CurrentUser -Force
    }
    Import-Module $module
}

# Script variables
# External settings
$storageAccountName = $ElysiumSettings['storageAccountName']
$containerName = $ElysiumSettings['containerName']
$sasToken = $ElysiumSettings['sasToken']

# Retrieve the passphrase from a user environment variable
$passphrase = [System.Environment]::GetEnvironmentVariable("ELYSIUM_PASSPHRASE", [System.EnvironmentVariableTarget]::User)

# Dynamic variables
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$domainPrefix = $selectedDomain.Name -replace "\W", "_" # Replace non-alphanumeric characters to ensure a valid file name
$exportPath = ".\${domainPrefix}_NTLM_Hashes_$timestamp.txt"
$compressedFilePath = ".\${domainPrefix}_NTLM_Hashes_$timestamp.zip"
$encryptedFilePath = ".\${domainPrefix}_NTLM_Hashes_$timestamp.enc"
$blobName = "${domainPrefix}_NTLM_Hashes_$timestamp.enc"

function Protect-FileWithAES {
    param (
        [Parameter(Mandatory = $true)]
        [string]$InputFile,

        [Parameter(Mandatory = $true)]
        [string]$OutputFile,

        [Parameter(Mandatory = $true)]
        [string]$Passphrase
    )

    $aes = New-Object System.Security.Cryptography.AesManaged
    $aes.KeySize = 256
    $aes.BlockSize = 128
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC

    # Generate key from passphrase
    $passwordBytes = [System.Text.Encoding]::UTF8.GetBytes($Passphrase)
    $aes.Key = [System.Security.Cryptography.SHA256]::Create().ComputeHash($passwordBytes)

    # Generate a random IV
    $aes.GenerateIV()

    $encryptor = $aes.CreateEncryptor($aes.Key, $aes.IV)

    $fileStream = [System.IO.File]::Open($InputFile, [System.IO.FileMode]::Open)
    $outFileStream = [System.IO.File]::Create($OutputFile)
    # Write the IV at the beginning of the output file
    $outFileStream.Write($aes.IV, 0, $aes.IV.Length)

    $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($outFileStream, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)

    try {
        $buffer = New-Object Byte[] 8192
        while (($read = $fileStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $cryptoStream.Write($buffer, 0, $read)
        }
    }
    finally {
        $cryptoStream.Close()
        $outFileStream.Close()
        $fileStream.Close()
        $aes.Clear()
    }

    Write-Host "File has been encrypted: $OutputFile"
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
$exportPath = ".\NTLM_Hashes_$timestamp.txt"
$compressedFilePath = ".\NTLM_Hashes_$timestamp.zip"

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
$storageContext = New-AzStorageContext -StorageAccountName $storageAccountName -SasToken "$sasToken"

# Upload the encrypted file to Azure Blob Storage
Set-AzStorageBlobContent -File $encryptedFilePath -Container $containerName -Blob $blobName -Context $storageContext
Write-Host "Encrypted file uploaded to Azure Blob Storage: $blobName"

# Download the blob to a temporary location to verify
$tempDownloadPath = [System.IO.Path]::GetTempFileName()
Get-AzStorageBlobContent -Blob $blobName -Container $containerName -Context $storageContext -Destination $tempDownloadPath -Force

# Calculate the downloaded file checksum
$downloadedFileChecksum = Get-FileChecksum -Path $tempDownloadPath

# Compare the checksums
if ($localFileChecksum -eq $downloadedFileChecksum) {
    Write-Host "The file was correctly uploaded. Checksum verified."
}
else {
    Write-Host "Checksum verification failed. The uploaded file may be corrupted."
}

# Clean up local and temporary files
Remove-Item -Path $exportPath, $compressedFilePath, $encryptedFilePath, $tempDownloadPath -Force
Write-Host "Local and temporary files cleaned up after uploading to Azure Blob Storage."

Write-Host "Script execution completed."
