##################################################
##   ____ ___  ____  _____   _   _ _____ _____  ##
##  / ___/ _ \|  _ \| ____| | \ | | ____|_   _| ##
## | |  | | | | |_) |  _|   |  \| |  _|   | |   ##
## | |__| |_| |  _ <| |___ _| |\  | |___  | |   ##
##  \____\__\_\_| \_\_____(_)_| \_|_____| |_|   ##
##################################################
## Project: Elysium                             ##
## File: Update-KHDB.ps1                        ##
## Version: 1.0                                 ##
## Support: support@cqre.net                    ##
##################################################

<#
.SYNOPSIS
Known hashes database update script for the Elysium AD password testing tool.

.DESCRIPTION
This script download khdb.txt.zip from designated Azure Stroage account, decompress it and overwrite the current version.
#>

# Initialize an empty hashtable to store settings
$ElysiumSettings = @{}

# Read the settings file
$settingsPath = "ElysiumSettings.txt"
Get-Content $settingsPath | ForEach-Object {
    $keyValue = $_ -split '=', 2
    $ElysiumSettings[$keyValue[0]] = $keyValue[1]
}

# Get variables related to Azure Blob storage
$AzureBlobStorageUrl = $ElysiumSettings["AzureBlobStorageUrl"] # Ensure this is properly constructed in your settings
$SecureToken = $ElysiumSettings["SecureToken"]

function Update-KHDB {
    Write-Host "Downloading KHDB..."

    # Setting request headers
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", "Bearer $SecureToken")

    # Downloading KHDB.zip from Azure Blob Storage
    $khdbZipPath = "khdb.zip"
    try {
        Invoke-WebRequest -Uri $AzureBlobStorageUrl -Headers $headers -OutFile $khdbZipPath
        Write-Host "KHDB.zip downloaded successfully."
    } catch {
        Write-Error "Error downloading KHDB.zip: $_"
        return
    }

    # Decompressing KHDB.zip
    try {
        Expand-Archive -Path $khdbZipPath -DestinationPath . -Force
        Remove-Item -Path $khdbZipPath -Force # Delete the zip file
        Write-Host "KHDB decompressed and cleaned up successfully."
    } catch {
        Write-Error "Error decompressing KHDB: $_"
        return
    }
}

# Run the script

Update-KHDB

Write-Host "Script execution completed."