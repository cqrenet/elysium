Set-StrictMode -Version Latest
# Module functions resolve preference variables through the module scope, not the caller's, so the
# root scripts' $ErrorActionPreference = 'Stop' would not reach them without this.
$ErrorActionPreference = 'Stop'

$script:ElysiumVersion = (Import-PowerShellDataFile -Path (Join-Path -Path $PSScriptRoot -ChildPath 'Elysium.psd1')).ModuleVersion
# ponytail: settings, KHDB and Reports still live in the repo root next to the scripts; this moves
# to $env:ProgramData\Elysium together with the .psd1 config.
$script:InstallRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent

foreach ($folder in 'Private', 'Public') {
    foreach ($file in Get-ChildItem -Path (Join-Path -Path $PSScriptRoot -ChildPath $folder) -Filter '*.ps1') {
        . $file.FullName
    }
}
