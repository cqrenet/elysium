##################################################
##   ____ ___  ____  _____   _   _ _____ _____  ##
##  / ___/ _ \|  _ \| ____| | \ | | ____|_   _| ##
## | |  | | | | |_) |  _|   |  \| |  _|   | |   ##
## | |__| |_| |  _ <| |___ _| |\  | |___  | |   ##
##  \____\__\_\_| \_\_____(_)_| \_|_____| |_|   ##
##          Move fast and fix things.           ##
##################################################
## Project: Elysium                             ##
## File: Test-WeakADPasswords.ps1               ##
## Version: 1.0.1                               ##
## Support: support@cqre.net                    ##
##################################################

<#
.SYNOPSIS
Weak AD password finder component of Elysium tool.

.DESCRIPTION
This script will test the passwords of selected domain (defined in ElysiumSettings.txt) using DSInternals' Test-PasswordQuality cmdlet. It writes its output to a report file which is meant to be shared with the internal security team.
#>

# Current timestamp for both report generation and header
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

# Define Header and Footer for the report with dynamic date
$header = @"
=========== Elysium Report ==========
Report Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
=====================================

"@
$footer = "`r`n==== End of Report ===="

# Import settings
Write-Host "Loading settings..."
$ElysiumSettings = @{}
$settingsPath = "ElysiumSettings.txt"

# Ensure the settings file exists
if (-not (Test-Path $settingsPath)) {
    Write-Error "Settings file not found at $settingsPath"
    exit
}

# Load settings from file
Get-Content $settingsPath | ForEach-Object {
    if (-not [string]::IsNullOrWhiteSpace($_) -and -not $_.StartsWith("#")) {
        $keyValue = $_ -split '=', 2
        if ($keyValue.Count -eq 2) {
            $ElysiumSettings[$keyValue[0].Trim()] = $keyValue[1].Trim()
        }
    }
}

# Define the function to extract domain details from settings
function Get-DomainDetailsFromSettings {
    param (
        [hashtable]$Settings
    )

    $domainDetails = @{}
    $counter = 1
    while ($true) {
        $nameKey = "Domain${counter}Name"
        $dcKey = "Domain${counter}DC"
        if ($Settings.ContainsKey($nameKey)) {
            $domainDetails["$counter"] = @{
                Name = $Settings[$nameKey]
                DC   = $Settings[$dcKey]
            }
            $counter++
        }
        else {
            break
        }
    }
    return $domainDetails
}

# Continue with script logic...
$domainDetails = Get-DomainDetailsFromSettings -Settings $ElysiumSettings

# Required modules
$requiredModules = @("DSInternals", "ActiveDirectory")

# Check each required module and import
foreach ($module in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Error "Required module '$module' is not installed. Please install it to proceed."
        exit
    }
    Import-Module $module
}

# Verify the existence of the Weak Password Hashes file
$WeakHashesSortedFilePath = Join-Path -Path $ElysiumSettings["InstallationPath"] -ChildPath $ElysiumSettings["WeakPasswordsDatabase"]
if (-not (Test-Path $WeakHashesSortedFilePath)) {
    Write-Error "Weak password hashes file not found at '$WeakHashesSortedFilePath'."
    exit
}

# Ensure the report directory exists
$reportPathBase = $ElysiumSettings["ReportPathBase"]
if (-not (Test-Path -Path $reportPathBase)) {
    New-Item -Path $reportPathBase -ItemType Directory
}

# Function to test for weak AD passwords
function Test-WeakADPasswords {
    param (
        [hashtable]$DomainDetails,
        [string]$FilePath
    )

    # User selects a domain
    Write-Host "Select a domain to test:"
    $DomainDetails.GetEnumerator() | ForEach-Object { Write-Host "$($_.Key): $($_.Value.Name)" }
    $selection = Read-Host "Enter the number of the domain"
    $selectedDomain = $DomainDetails[$selection]

    if (-not $selectedDomain) {
        Write-Error "Invalid selection."
        return
    }

    # Prompt for DA credentials
    $credential = Get-Credential -Message "Enter AD credentials with replication rights for $($selectedDomain.Name)"

    # Performing the test
    Write-Host "Testing password quality for $($selectedDomain.Name)..."
    $testResults = Get-ADReplAccount -All -Server $selectedDomain["DC"] -Credential $credential |
    Test-PasswordQuality -WeakPasswordHashesFile $FilePath

    # Report generation with dynamic content
    $reportPath = Join-Path -Path $reportPathBase -ChildPath "$($selectedDomain.Name)_WeakPasswordReport_$timestamp.txt"
    $reportContent = @($header, ($testResults | Out-String).Trim(), $footer) -join "`r`n"
    $reportContent | Out-File -FilePath $reportPath
    Write-Host "Report saved to $reportPath"
}

# Main script logic
Test-WeakADPasswords -DomainDetails $domainDetails -FilePath $WeakHashesSortedFilePath

Write-Host "Script execution completed."
