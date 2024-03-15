# Import settings
Write-Host "Loading settings..."
$ElysiumSettings = @{}
$settingsPath = "ElysiumSettings.txt"

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

# Import required modules
Import-Module DSInternals
Import-Module ActiveDirectory

# Get the variables from settings
$WeakHashesSortedFilePath = $ElysiumSettings["WeakPasswordsDatabase"]

# Function to test for weak AD passwords
function Test-WeakADPasswords {
    param (
        [string]$WeakHashesSortedFilePath
    )

    Write-Host "Starting the test for weak AD passwords..."

    Write-Host "Enumerating accounts from the domain controller..."
    $accounts = Get-ADReplAccount -All -Server dc01-bmr -Credential (Get-Credential)

    Write-Host "Testing password quality..."
    $accounts | Test-PasswordQuality -WeakPasswordHashesFile $WeakHashesSortedFilePath

    # Debug: Print results
    $accounts | Format-Table
}
