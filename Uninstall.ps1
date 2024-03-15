<#
.SYNOPSIS
Uninstall script for the Elysium AD password testing tool.

.DESCRIPTION
This script will remove the Elysium tool and its components (scripts, configurations, and any generated data) from the system.
#>

# Define the path where the Elysium tool is installed
$ElysiumPath = "C:\Path\To\Elysium" # Update this with the actual installation path

function Uninstall-Elysium {
    Write-Host "Uninstalling Elysium tool..."

    # Check if the Elysium directory exists
    if (Test-Path $ElysiumPath) {
        # Remove the Elysium directory and all its contents
        Remove-Item -Path $ElysiumPath -Recurse -Force
        Write-Host "Elysium tool and all related files have been removed."
    } else {
        Write-Host "Elysium directory not found. It might have been removed already or the path is incorrect."
    }

    # Additional cleanup actions can be added here if needed
}

# Execute the uninstall function
Uninstall-Elysium

# Confirm uninstallation
Write-Host "Elysium tool has been successfully uninstalled." -ForegroundColor Green
