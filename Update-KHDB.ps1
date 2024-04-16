##################################################
##   ____ ___  ____  _____   _   _ _____ _____  ##
##  / ___/ _ \|  _ \| ____| | \ | | ____|_   _| ##
## | |  | | | | |_) |  _|   |  \| |  _|   | |   ##
## | |__| |_| |  _ <| |___ _| |\  | |___  | |   ##
##  \____\__\_\_| \_\_____(_)_| \_|_____| |_|   ##
##################################################
## Project: Elysium                             ##
## File: Update-KHDB.ps1                        ##
## Version: 1.0.1                               ##
## Support: support@cqre.net                    ##
##################################################

<#
.SYNOPSIS
Known hashes database update script for the Elysium AD password testing tool.

.DESCRIPTION
This script downloads khdb.txt.zip from the designated Azure Storage account, decompresses it, and overwrites the current version.
#>

# Initialize an empty hashtable to store settings
$ElysiumSettings = @{}

# Read the settings file
$settingsPath = "ElysiumSettings.txt"
Get-Content $settingsPath | ForEach-Object {
    if ($_ -notmatch '^#' -and $_.Trim()) {
        $keyValue = $_.Split('=', 2)
        $key = $keyValue[0].Trim()
        $value = $keyValue[1].Trim().Trim("'")
        $ElysiumSettings[$key] = $value
    }
}

# Verify that all required settings have been loaded
if (-not $ElysiumSettings.ContainsKey("storageAccountName") -or
    -not $ElysiumSettings.ContainsKey("containerName") -or
    -not $ElysiumSettings.ContainsKey("sasToken")) {
    Write-Error "Missing required settings. Please check your settings file."
    return
}

# Construct the full URL for accessing the Azure Blob Storage
$storageAccountName = $ElysiumSettings["storageAccountName"]
$containerName = $ElysiumSettings["containerName"]
$sasToken = $ElysiumSettings["sasToken"]
$AzureBlobStorageUrl = "https://$storageAccountName.blob.core.windows.net/$containerName/khdb.txt.zip$sasToken"

# Load necessary .NET assembly for HTTP operations
Add-Type -AssemblyName System.Net.Http
function Update-KHDB {
    Write-Host "Downloading KHDB..."

    # Initialize the client for downloading the file
    $httpClient = New-Object System.Net.Http.HttpClient

    try {
        # Start the asynchronous request to download the file
        $response = $httpClient.GetAsync($AzureBlobStorageUrl, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).Result

        if ($response.IsSuccessStatusCode) {
            $totalBytes = $response.Content.Headers.ContentLength
            $totalRead = 0
            $read = 0
            $buffer = New-Object byte[] 8192
            $stream = $response.Content.ReadAsStreamAsync().Result
            $fileStream = [System.IO.File]::Create("khdb.txt.zip")

            # Read the stream in chunks and update the progress bar
            while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $fileStream.Write($buffer, 0, $read)
                $totalRead += $read
                $percentage = ($totalRead * 100) / $totalBytes
                Write-Progress -Activity "Downloading khdb.txt.zip" -Status "$([Math]::Round($percentage, 2))% Complete:" -PercentComplete $percentage
            }

            $fileStream.Close()
            Write-Host "KHDB.zip downloaded successfully."
        } else {
            Write-Error "Failed to download khdb.txt.zip: $($response.StatusCode)"
        }
    } catch {
        Write-Error "Error during download: $_"
        return
    }

    # Decompressing KHDB.zip
    try {
        Expand-Archive -Path "khdb.txt.zip" -DestinationPath . -Force
        Remove-Item -Path "khdb.txt.zip" -Force # Delete the zip file after extraction
        Write-Host "KHDB decompressed and cleaned up successfully."
    } catch {
        Write-Error "Error decompressing KHDB: $_"
        return
    }
}

# Execute the update function
Update-KHDB
Write-Host "Script execution completed."
