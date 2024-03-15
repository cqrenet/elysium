<#
.SYNOPSIS
This is the main script for the Elysium tool for testing weak AD passwords.

.DESCRIPTION
Elysium.ps1 offers a menu to perform various actions:
1. Update Known-Hashes Database (KHDB)
2. Test Weak AD Passwords
3. Extract and Send Current Hashes for KHDB Update
4. Exit
#>

function Show-Menu {
    param (
        [string]$Title = 'Elysium Tool Main Menu'
    )
    Clear-Host
    Write-Host "================ $Title ================"

    Write-Host "1: Update Known-Hashes Database (KHDB)"
    Write-Host "2: Test Weak AD Passwords"
    Write-Host "3: Extract and Send Current Hashes for KHDB Update"
    Write-Host "4: Exit"
}

do {
    Show-Menu
    $input = Read-Host "Please make a selection"
    switch ($input) {
        '1' {
            Write-Host "Updating KHDB..."
            .\Update-KHDB.ps1
        }
        '2' {
            Write-Host "Testing Weak AD Passwords..."
            .\Test-WeakADPasswords.ps1
        }
        '3' {
            Write-Host "Extracting and Sending Current Hashes..."
            .\Send-CurrentHashes.ps1
        }
        '4' {
            Write-Host "Exiting..."
            exit
        }
        default {
            Write-Host "Invalid selection, please try again."
        }
    }
    pause
} while ($input -ne '4')
