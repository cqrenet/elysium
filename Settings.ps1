# Settings for Elysium Tool

# General Settings
$Global:ToolRepositoryUrl = "https://example.com/git/elysium.git"

# KHDB Update Settings
$Global:KnownHashesBaseUrl = "https://example.com/known-hashes/"
$Global:LocalKnownHashesPath = "C:\Elysium\known-hashes"

# Test Weak AD Passwords Settings
$Global:DomainAdminUsernames = @{
    "Domain1" = "admin1";
    "Domain2" = "admin2";
    # Add more domains and usernames as needed
}
$Global:PdfReportPath = "C:\Elysium\Reports"

# Extract and Send Hashes Settings
$Global:HashesExportPath = "C:\Elysium\Hashes"
$Global:ToolProviderUploadUrl = "https://upload.example.com/hashes"

# Any additional settings...
