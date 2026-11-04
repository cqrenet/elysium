Set-StrictMode -Version Latest
# Module functions resolve preference variables through the module scope, not the caller's, so the
# root scripts' $ErrorActionPreference = 'Stop' would not reach them without this.
$ErrorActionPreference = 'Stop'

$script:ModuleManifestPath = Join-Path -Path $PSScriptRoot -ChildPath 'Elysium.psd1'
$script:ElysiumVersion = (Import-PowerShellDataFile -Path $ModuleManifestPath).ModuleVersion
# Process-wide; Windows PowerShell 5.1's HttpClient otherwise may not offer TLS 1.2.
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
# ponytail: settings, KHDB and Reports still live in the repo root next to the scripts; this moves
# to $env:ProgramData\Elysium together with the .psd1 config.
$script:InstallRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent

foreach ($folder in 'Private', 'Public') {
    foreach ($file in Get-ChildItem -Path (Join-Path -Path $PSScriptRoot -ChildPath $folder) -Filter '*.ps1') {
        . $file.FullName
    }
}
