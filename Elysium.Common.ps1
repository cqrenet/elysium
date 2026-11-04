# Transitional loader. The shared helpers now live in the Elysium module (src/Elysium/Private);
# root scripts that dot-source this file keep getting them in their own scope until each script
# is converted to a module cmdlet.
$script:ElysiumVersion = (Import-PowerShellDataFile -Path (Join-Path -Path $PSScriptRoot -ChildPath 'src/Elysium/Elysium.psd1')).ModuleVersion
foreach ($helperFile in Get-ChildItem -Path (Join-Path -Path $PSScriptRoot -ChildPath 'src/Elysium/Private') -Filter '*.ps1') {
    . $helperFile.FullName
}
