# Transcript logging into <BasePath>/Reports/logs/<Name>-<timestamp>.log. A failure to start the
# transcript is a warning, never a reason to abort the operation itself.

function Start-ElysiumTranscript {
    param(
        [Parameter(Mandatory)][string]$BasePath,
        [Parameter(Mandatory)][string]$Name
    )
    try {
        $logsDir = Join-Path -Path $BasePath -ChildPath 'Reports/logs'
        if (-not (Test-Path $logsDir)) { New-Item -Path $logsDir -ItemType Directory -Force | Out-Null }
        $ts = Get-Date -Format 'yyyyMMdd-HHmmss'
        $logPath = Join-Path -Path $logsDir -ChildPath "$Name-$ts.log"
        Start-Transcript -Path $logPath -Force | Out-Null
    } catch {
        Write-Warning "Could not start transcript: $($_.Exception.Message)"
    }
}

function Stop-ElysiumTranscript { try { Stop-Transcript | Out-Null } catch {} }
