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
## Version: 1.1.0                               ##
## Support: support@cqre.net                    ##
##################################################

<#
.SYNOPSIS
Weak AD password finder component of Elysium tool.

.DESCRIPTION
This script will test the passwords of selected domain (defined in ElysiumSettings.txt) using DSInternals' Test-PasswordQuality cmdlet. It writes its output to a report file which is meant to be shared with the internal security team. The report now includes UPNs for each account mentioned.
#>

# Enable verbose output
$VerbosePreference = "Continue"

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
Write-Verbose "Loading settings..."
$ElysiumSettings = @{}
$settingsPath = "ElysiumSettings.txt"

# Ensure the settings file exists
if (-not (Test-Path $settingsPath)) {
    Write-Error "Settings file not found at $settingsPath"
    exit
}

# Load settings from file
try {
    Get-Content $settingsPath | ForEach-Object {
        if (-not [string]::IsNullOrWhiteSpace($_) -and -not $_.StartsWith("#")) {
            $keyValue = $_ -split '=', 2
            if ($keyValue.Count -eq 2) {
                $ElysiumSettings[$keyValue[0].Trim()] = $keyValue[1].Trim()
            }
        }
    }
    Write-Verbose "Settings loaded successfully."
} catch {
    Write-Error ("An error occurred while loading settings: {0}" -f $_.Exception.Message)
    exit
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
Write-Verbose ("Domain details extracted: {0}" -f ($domainDetails | ConvertTo-Json))

# Required modules
$requiredModules = @("DSInternals", "ActiveDirectory")

# Check each required module and import
foreach ($module in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Verbose "Required module '$module' is not installed."
        $response = Read-Host "Would you like to install it? (Y/N)"
        if ($response -eq 'Y') {
            try {
                Install-Module -Name $module -Force -ErrorAction Stop
                Write-Verbose "Module '$module' installed successfully."
            } catch {
                Write-Error ("Failed to install module '{0}': {1}" -f $module, $_.Exception.Message)
                exit
            }
        } else {
            Write-Error "Required module '$module' is not installed. Please install it to proceed."
            exit
        }
    }
    Import-Module $module
    Write-Verbose "Module '$module' imported."
}

# Verify the existence of the Weak Password Hashes file
$WeakHashesSortedFilePath = Join-Path -Path $ElysiumSettings["InstallationPath"] -ChildPath $ElysiumSettings["WeakPasswordsDatabase"]
if (-not (Test-Path $WeakHashesSortedFilePath)) {
    Write-Error "Weak password hashes file not found at '$WeakHashesSortedFilePath'."
    exit
}
Write-Verbose "Weak password hashes file found at '$WeakHashesSortedFilePath'."

# Ensure the report directory exists
$reportPathBase = $ElysiumSettings["ReportPathBase"]
if (-not (Test-Path -Path $reportPathBase)) {
    try {
        New-Item -Path $reportPathBase -ItemType Directory -ErrorAction Stop
        Write-Verbose "Report directory created at '$reportPathBase'."
    } catch {
        Write-Error ("Failed to create report directory: {0}" -f $_.Exception.Message)
        exit
    }
}

# Function to get UPN for a given SAM account name
function Get-UserUPN {
    param (
        [string]$SamAccountName,
        [string]$Domain,
        [System.Management.Automation.PSCredential]$Credential
    )
    
    Write-Verbose "Attempting to get UPN for $SamAccountName in domain $Domain"
    try {
        $user = Get-ADUser -Identity $SamAccountName -Properties UserPrincipalName -Server $Domain -Credential $Credential
        Write-Verbose "UPN found: $($user.UserPrincipalName)"
        return $user.UserPrincipalName
    } catch {
        Write-Verbose ("Failed to get UPN for {0}: {1}" -f $SamAccountName, $_.Exception.Message)
        return "UPN not found"
    }
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
    
    if (-not ($DomainDetails.ContainsKey($selection))) {
        Write-Error "Invalid selection."
        return
    }
    
    $selectedDomain = $DomainDetails[$selection]
    Write-Verbose "Selected domain: $($selectedDomain.Name)"

    # Prompt for DA credentials
    $credential = Get-Credential -Message "Enter AD credentials with replication rights for $($selectedDomain.Name)"

    # Performing the test
    Write-Verbose "Testing password quality for $($selectedDomain.Name)..."
    try {
        $testResults = Get-ADReplAccount -All -Server $selectedDomain["DC"] -Credential $credential |
        Test-PasswordQuality -WeakPasswordHashesFile $FilePath
        Write-Verbose "Password quality test completed."
    } catch {
        Write-Error ("An error occurred while testing passwords: {0}" -f $_.Exception.Message)
        return
    }

    # Report generation with dynamic content and UPNs
    $reportPath = Join-Path -Path $reportPathBase -ChildPath "$($selectedDomain.Name)_WeakPasswordReport_$timestamp.txt"
    Write-Verbose "Generating report at $reportPath"
    $reportContent = @($header, ($testResults | Out-String).Trim(), $footer) -join "`r`n"
    
    $lines = $reportContent -split "`r`n"
    $newReportContent = @()

    foreach ($line in $lines) {
        $newReportContent += $line
        
        if ($line -match "$($selectedDomain.Name)\\(.+)") {
            $samAccountName = $matches[1]
            Write-Verbose "Looking up UPN for $samAccountName"
            $upn = Get-UserUPN -SamAccountName $samAccountName -Domain $selectedDomain.DC -Credential $credential
            $newReportContent += "    UPN: $upn"
        }
    }

    $updatedReportContent = $newReportContent -join "`r`n"

    try {
        $updatedReportContent | Out-File -FilePath $reportPath -ErrorAction Stop
        Write-Host "Report saved to $reportPath"
    } catch {
        Write-Error ("Failed to save report: {0}" -f $_.Exception.Message)
    }
}

# Main script logic
try {
    Write-Verbose "Starting main script execution..."
    Test-WeakADPasswords -DomainDetails $domainDetails -FilePath $WeakHashesSortedFilePath
} catch {
    Write-Error ("An error occurred during script execution: {0}" -f $_.Exception.Message)
}

Write-Host "Script execution completed."
