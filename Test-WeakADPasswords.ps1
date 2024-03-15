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
## Version: 0.1                                 ##
## Support: support@cqre.net                    ##
##################################################

# Import settings
Write-Host "Loading settings..."
$ElysiumSettings = @{}
$settingsPath = "ElysiumSettings.txt"

if (-not (Test-Path $settingsPath)) {
    Write-Error "Settings file not found at $settingsPath"
    return
}

Get-Content $settingsPath | ForEach-Object {
    if (-not [string]::IsNullOrWhiteSpace($_) -and -not $_.StartsWith("#")) {
        $keyValue = $_ -split '=', 2
        if ($keyValue.Count -eq 2) {
            $ElysiumSettings[$keyValue[0]] = $keyValue[1]
        }
    }
}

$WeakHashesSortedFilePath = Join-Path -Path $ElysiumSettings["InstallationPath"] -ChildPath $ElysiumSettings["WeakPasswordsDatabase"]
if (-not (Test-Path $WeakHashesSortedFilePath)) {
    Write-Error "Weak password hashes file not found at '$WeakHashesSortedFilePath'."
    return
}

# Check if required modules are available and install them if necessary
$requiredModules = @("DSInternals", "ActiveDirectory")
foreach ($module in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        $userConsent = Read-Host "Module '$module' is not installed. Do you want to install it now? (Y/N)"
        if ($userConsent -eq 'Y') {
            try {
                Write-Host "Installing module '$module'..."
                Install-Module -Name $module -Force -Scope CurrentUser
                Write-Host "Module '$module' installed successfully."
            } catch {
                Write-Error "Failed to install module '$module'. Error: $_"
                return
            }
        } else {
            Write-Host "Skipping module installation. Script may not function correctly without the required modules."
            return
        }
    }
}

# Import required modules
Import-Module DSInternals
Import-Module ActiveDirectory

# Get the variables from settings
$WeakHashesSortedFilePath = $ElysiumSettings["WeakPasswordsDatabase"]
# Get the report path from settings
$reportPathBase = $ElysiumSettings["ReportPathBase"]
if ($null -eq $reportPathBase) {
    Write-Error "Report path is not defined in the settings."
    return
}

# Check if the report directory exists, create it if it doesn't
if (-not (Test-Path -Path $reportPathBase)) {
    Write-Host "Report directory does not exist. Creating directory at $reportPathBase..."
    New-Item -Path $reportPathBase -ItemType Directory
}


# Function to extract domain details from settings
function Get-DomainDetailsFromSettings {
    param (
        [hashtable]$ElysiumSettings
    )

    Write-Host "Extracting domain details from settings..."
    $domainDetails = @{}
    $domainCounter = 1

    while ($true) {
        $domainNameKey = "Domain${domainCounter}Name"
        $domainDCKey = "Domain${domainCounter}DC"
        $domainDAKey = "Domain${domainCounter}DA"

        if ($ElysiumSettings.ContainsKey($domainNameKey)) {
            $domainDetails["$domainCounter"] = @{
                "Name" = $ElysiumSettings[$domainNameKey]
                "DC"   = $ElysiumSettings[$domainDCKey]
                "DA"   = $ElysiumSettings[$domainDAKey]
            }
            $domainCounter++
        } else {
            break
        }
    }

    return $domainDetails
}

# Function to test for weak AD passwords
function Test-WeakADPasswords {
    param (
        [hashtable]$DomainDetails,
        [string]$WeakHashesSortedFilePath
    )

    Write-Host "Starting the test for weak AD passwords..."

    # Display domain options to the user
    Write-Host "Select a domain to test:"
    $sortedDomains = $DomainDetails.Keys | Sort-Object
    foreach ($domain in $sortedDomains) {
        $domainName = $DomainDetails[$domain].Name
        Write-Host ($domain + ": " + $domainName)
    }

    # User selects a domain
    $selectedDomainKey = Read-Host "Enter the number of the domain"
    $selectedDomain = $DomainDetails[$selectedDomainKey]

    if ($null -eq $selectedDomain) {
        Write-Error "Invalid selection. Exiting."
        return $null
    }

    # Prompt for DA password
    $DAUsername = $selectedDomain["DA"]
    $DApassword = Read-Host "Enter password for DA account ($DAUsername) of $($selectedDomain.Name)" -AsSecureString

    # Preparing credentials for the domain
    $credentials = New-Object System.Management.Automation.PSCredential($selectedDomain.DA, $DApassword)

    Write-Host "Enumerating accounts from the domain controller $($selectedDomain.DC)..."
    $accounts = Get-ADReplAccount -All -Server $selectedDomain.DC -Credential $credentials

    Write-Host "Testing password quality..."
    $testResults = $accounts | Test-PasswordQuality -WeakPasswordHashesFile $WeakHashesSortedFilePath

    # Debug: Print selected domain details
    Write-Host "Selected domain details: Name=$($selectedDomain.Name), DC=$($selectedDomain.DC), DA=$($selectedDomain.DA)"

    # Generate report name and path
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $reportName = $selectedDomain.Name + "_WeakPasswordReport_" + $timestamp + ".txt"
    $reportPath = Join-Path -Path $reportPathBase -ChildPath $reportName

    Write-Host "Report will be saved as: $reportName"

    # Return a hashtable with report path and weak accounts
    return @{
        "ReportPath" = $reportPath;
        "WeakAccounts" = $testResults.WeakPasswords;
    }
}

# Function to export weak password report
function Export-WeakPasswordReport {
    param (
        [array]$WeakAccounts,
        [string]$ReportPath
    )

    Write-Host "Exporting weak password report to $ReportPath"

    # Handle empty weak accounts array
    if ($null -eq $WeakAccounts -or $WeakAccounts.Count -eq 0) {
        "No weak passwords found." | Out-File $ReportPath
    } else {
        $WeakAccounts | Out-File $ReportPath
    }
    
    Write-Host "Weak password report generated at $ReportPath"
}

# Main script execution
try {
    $domainDetails = Get-DomainDetailsFromSettings -ElysiumSettings $ElysiumSettings
    $results = Test-WeakADPasswords -DomainDetails $domainDetails -WeakHashesSortedFilePath $WeakHashesSortedFilePath

    # Check if results were returned before proceeding
    if ($results) {
        # Generate the report
        Export-WeakPasswordReport -WeakAccounts $results.WeakAccounts -ReportPath $results.ReportPath

        # Check if there are weak accounts
        if ($results.WeakAccounts) {
            Write-Host "Weak passwords found. Report generated at $($results.ReportPath)"
        } else {
            Write-Host "No weak passwords found. Empty report generated at $($results.ReportPath)"
        }
    }
} catch {
    Write-Error "An error occurred: $_"
}

Write-Host "Script execution completed."
