@{
    RootModule        = 'Elysium.psm1'
    # Single source of the project version: the root scripts, User-Agent strings and the usage
    # beacon all read it from here.
    ModuleVersion     = '2.6.0'
    GUID              = '01fbd208-0a80-42b4-b464-3be903feeb25'
    Author            = 'CQRE.NET'
    CompanyName       = 'CQRE.NET'
    Description       = 'Active Directory weak-password assessment: KHDB updates, DSInternals password-quality tests, hash export, Lithnet Password Protection import.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Update-ElysiumKhdb', 'Update-ElysiumLithnetStore', 'Test-ElysiumPasswordQuality', 'Send-ElysiumHashExport')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
