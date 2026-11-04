##################################################
##   ____ ___  ____  _____   _   _ _____ _____  ##
##  / ___/ _ \|  _ \| ____| | \ | | ____|_   _| ##
## | |  | | | | |_) |  _|   |  \| |  _|   | |   ##
## | |__| |_| |  _ <| |___ _| |\  | |___  | |   ##
##  \____\__\_\_| \_\_____(_)_| \_|_____| |_|   ##
##################################################
## Project: Elysium                             ##
## File: Prepare-KHDBStorage.ps1                ##
## Support: support@cqre.net                    ##
##################################################

<#
.SYNOPSIS
Prepares sharded KHDB content for remote storage.

.DESCRIPTION
Provider-side tool. Splits a KHDB source (a sorted khdb.txt, or a directory/list of
Have I Been Pwned .gz slices) into hash-prefix shards and writes manifest.json with the
SHA-256 and size of every shard, in the layout Update-ElysiumKhdb downloads. Invalid
lines go to invalid-hashes.txt; khdb-clean.txt holds the merged, cleaned list.

It does not upload. Publish the package with the storage provider's own CLI, shards
first and manifest.json last, so clients never see a manifest that points at shards
that are not there yet (see the README for aws s3 / rclone / azcopy commands).
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$SourcePath,

    [string]$OutputRoot,

    [ValidateRange(1, 8)]
    [int]$ShardSize = 2,

    [string]$ManifestVersion,

    # Where the shards will live in the bucket/container; written into the manifest so clients
    # know where to fetch them from. Upload the shards to this same path.
    [string]$ShardRemotePrefix = 'khdb/shards',

    [switch]$ShowProgress,
    [int]$ProgressUpdateInterval = 100000,

    [switch]$ForcePlainText,

    [string]$CheckpointPath,
    [switch]$NoCheckpoint,

    [switch]$Force
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue

function Ensure-Directory {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }
}

function Remove-DirectoryContents {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    Get-ChildItem -LiteralPath $Path -Force | ForEach-Object {
        Remove-Item -LiteralPath $_.FullName -Recurse -Force
    }
}

function Merge-ShardsToFile {
    param(
        [psobject]$Manifest,
        [string]$ShardsRoot,
        [string]$TargetPath
    )

    $encoding = New-Object System.Text.UTF8Encoding($false)
    $writer = New-Object System.IO.StreamWriter($TargetPath, $false, $encoding, 1048576)
    try {
        foreach ($entry in ($Manifest.shards | Sort-Object name)) {
            $relative = [string]$entry.name
            if ([string]::IsNullOrWhiteSpace($relative)) { continue }
            $shardPath = Join-Path -Path $ShardsRoot -ChildPath $relative
            if (-not (Test-Path -LiteralPath $shardPath)) {
                throw "Missing shard on disk: $relative"
            }
            $reader = New-Object System.IO.StreamReader($shardPath, [System.Text.Encoding]::UTF8, $true, 1048576)
            try {
                while (($line = $reader.ReadLine()) -ne $null) {
                    $trimmed = $line.Trim()
                    if ($trimmed.Length -gt 0) { $writer.WriteLine($trimmed) }
                }
            } finally {
                $reader.Dispose()
            }
        }
    } finally {
        $writer.Dispose()
    }
}

function Get-NormalizedForwardPath {
    param([string]$PathValue)
    if ([string]::IsNullOrWhiteSpace($PathValue)) { return '' }
    return $PathValue.Replace('\', '/').Trim('/')
}

function Split-KhdbIntoShards {
    param(
        [string]$Source,
        [string]$ShardRoot,
        [int]$PrefixLength,
        [string]$InvalidOutputPath,
        [switch]$ShowProgress,
        [int]$ProgressUpdateInterval = 100000,
        [string]$ProgressActivity = 'Splitting KHDB',
        [switch]$ForcePlainText,
        [switch]$EnableCheckpoint,
        [string]$CheckpointPath,
        [switch]$Resume,
        [psobject]$ResumeState
    )

    $hashRegex = '^[0-9A-Fa-f]{32}(:\d+)?$'
    $encoding = New-Object System.Text.UTF8Encoding($false)
    $ShardRoot = [System.IO.Path]::GetFullPath($ShardRoot)
    Ensure-Directory $ShardRoot

    if ($Resume -and -not $EnableCheckpoint) { throw 'Resume requested without a checkpoint.' }
    if ($EnableCheckpoint -and -not $ForcePlainText) { throw 'Checkpointing requires -ForcePlainText so the source is processed as plain text hashes.' }

    $shardStates = @{}
    $stats = @{}
    $resumeFilePosition = 0L

    # ValidEntries lives on $meta (a hashtable, i.e. reference type) rather than as its own scalar
    # variable because $processHashLine below is invoked via the call operator (&), which runs in
    # its own child scope - a bare scalar '$total++' inside it would silently increment a local
    # shadow copy and never update the caller's variable. Mutating a property on a shared
    # hashtable/object works fine across that scope boundary.
    $meta = @{
        TotalLines = 0L
        InvalidLines = 0L
        SkippedLines = 0L
        LegacyLines = 0L
        ValidEntries = 0L
        InvalidSamples = New-Object System.Collections.Generic.List[string]
    }

    if ($Resume -and $ResumeState) {
        if ($ResumeState.sourcePath -and ($ResumeState.sourcePath -ne $Source)) {
            throw "Checkpoint source '$($ResumeState.sourcePath)' does not match current source '$Source'."
        }
        if ($ResumeState.prefixLength -and ([int]$ResumeState.prefixLength -ne $PrefixLength)) {
            throw "Checkpoint prefix length $($ResumeState.prefixLength) does not match requested $PrefixLength."
        }
        if ($ResumeState.forcePlainText -ne $true) {
            throw 'Checkpoint was created without -ForcePlainText; resume is not supported in that mode.'
        }
        if ($ResumeState.shardRoot) {
            $resumeShardRoot = [System.IO.Path]::GetFullPath([string]$ResumeState.shardRoot)
            if ($resumeShardRoot -ne $ShardRoot) {
                throw "Checkpoint shard root '$resumeShardRoot' does not match target '$ShardRoot'."
            }
        }
        if ($ResumeState.totalLines) { $meta.TotalLines = [long]$ResumeState.totalLines }
        if ($ResumeState.invalidLines) { $meta.InvalidLines = [long]$ResumeState.invalidLines }
        if ($ResumeState.skippedLines) { $meta.SkippedLines = [long]$ResumeState.skippedLines }
        if ($ResumeState.validEntries) { $meta.ValidEntries = [long]$ResumeState.validEntries }
        if ($ResumeState.filePosition) { $resumeFilePosition = [long]$ResumeState.filePosition }
    }
    $plainReader = $null
    $plainBaseStream = $null

    # Pre-create all shard writers for the full prefix space (e.g., 256 for 2 hex digits)
    $prefixList = @()
    $prefixChars = '0123456789abcdef'
    function Get-AllPrefixes([int]$length) {
        if ($length -le 0) { return @('') }
        $subs = Get-AllPrefixes ($length - 1)
        $result = @()
        foreach ($c in $prefixChars.ToCharArray()) {
            foreach ($s in $subs) {
                $result += ($s + $c)
            }
        }
        return $result
    }
    $prefixList = Get-AllPrefixes $PrefixLength
    foreach ($prefix in $prefixList) {
        $shardPath = Join-Path -Path $ShardRoot -ChildPath ("$prefix.txt")
        Ensure-Directory (Split-Path -Path $shardPath -Parent)
        # Open with large buffer (1 MiB)
        $writer = New-Object System.IO.StreamWriter($shardPath, $false, $encoding, 1048576)
        $state = [ordered]@{
            Writer = $writer
            Path = $shardPath
            Count = 0
            PendingLine = $null
            PendingHash = $null
            PendingCount = -1
        }
        $shardStates[$prefix] = $state
    }

    $sourceItem = Get-Item -LiteralPath $Source -ErrorAction Stop
    if ($ForcePlainText -and $sourceItem.PSIsContainer) {
        throw 'ForcePlainText can only be used when SourcePath is a file. Provide a plain khdb.txt file, not a directory.'
    }
    if ($EnableCheckpoint -and $sourceItem.PSIsContainer) {
        throw 'Checkpointing/resume is only supported when SourcePath points to a plain hash file.'
    }
    $sourceBaseDir = if ($sourceItem.PSIsContainer) { $sourceItem.FullName } else { Split-Path -Parent $sourceItem.FullName }
    $currentSource = if ($sourceItem.PSIsContainer) { $sourceItem.FullName } else { $sourceItem.Name }

    $maxInvalidSamples = 10
    # Held in a hashtable so $ensureInvalidWriter (invoked with &, i.e. in a child scope) can set
    # it for the whole function; a plain variable assignment there would stay local to that call.
    $invalidOutput = @{ Writer = $null }
    $ensureInvalidWriter = {
        if (-not $InvalidOutputPath) { return }
        if (-not $invalidOutput.Writer) {
            $parent = Split-Path -Parent $InvalidOutputPath
            if ($parent) { Ensure-Directory $parent }
            $appendInvalid = $Resume -and (Test-Path -LiteralPath $InvalidOutputPath)
            $invalidOutput.Writer = New-Object System.IO.StreamWriter($InvalidOutputPath, $appendInvalid, $encoding, 1048576)
        }
    }

    if ($Resume -and $ResumeState -and $ResumeState.shardStates) {
        foreach ($resumeShard in $ResumeState.shardStates) {
            $prefix = [string]$resumeShard.prefix
            if ([string]::IsNullOrWhiteSpace($prefix)) { continue }
            $shardPath = Join-Path -Path $ShardRoot -ChildPath ("$prefix.txt")
            Ensure-Directory (Split-Path -Path $shardPath -Parent)
            $writer = New-Object System.IO.StreamWriter($shardPath, $true, $encoding, 1048576)
            $state = [ordered]@{
                Writer = $writer
                Path = $shardPath
                Count = if ($resumeShard.count -ne $null) { [long]$resumeShard.count } else { 0L }
                PendingLine = $resumeShard.pendingLine
                PendingHash = $resumeShard.pendingHash
                PendingCount = if ($resumeShard.pendingCount -ne $null) { [int]$resumeShard.pendingCount } else { -1 }
            }
            $shardStates[$prefix] = $state
        }
    }

    if ($ShowProgress) {
        if ($ProgressUpdateInterval -lt 1) { $ProgressUpdateInterval = 100000 }
    }
    $progressStopwatch = if ($ShowProgress) { [System.Diagnostics.Stopwatch]::StartNew() } else { $null }
    $checkpointEncoding = New-Object System.Text.UTF8Encoding($false)
    $saveCheckpoint = {
        param([long]$filePosition)
        if (-not $EnableCheckpoint) { return }
        foreach ($s in $shardStates.Values) { $s.Writer.Flush() }
        if ($invalidOutput.Writer) { $invalidOutput.Writer.Flush() }
        $payload = [ordered]@{
            version        = 1
            savedAt        = (Get-Date).ToUniversalTime().ToString('o')
            sourcePath     = $Source
            shardRoot      = $ShardRoot
            forcePlainText = [bool]$ForcePlainText
            prefixLength   = $PrefixLength
            mode           = 'Plain'
            filePosition   = $filePosition
            totalLines     = [long]$meta.TotalLines
            invalidLines   = [long]$meta.InvalidLines
            skippedLines   = [long]$meta.SkippedLines
            validEntries   = [long]$meta.ValidEntries
            shardStates    = @()
        }
        foreach ($entry in ($shardStates.GetEnumerator() | Sort-Object Key)) {
            $state = $entry.Value
            $payload.shardStates += [ordered]@{
                prefix       = $entry.Key
                count        = [long]$state.Count
                pendingLine  = $state.PendingLine
                pendingHash  = $state.PendingHash
                pendingCount = $state.PendingCount
            }
        }
        [System.IO.File]::WriteAllText($CheckpointPath, ($payload | ConvertTo-Json -Depth 6), $checkpointEncoding)
    }
    $invokeProgress = {
        param([bool]$Force = $false, [string]$Context)
        if (-not $ShowProgress) { return }
        if (-not $progressStopwatch) { return }
        $shouldUpdate = $Force
        if (-not $shouldUpdate) {
            if ($ProgressUpdateInterval -gt 0 -and $meta.TotalLines -gt 0 -and ($meta.TotalLines % $ProgressUpdateInterval) -eq 0) {
                $shouldUpdate = $true
            } elseif ($progressStopwatch.ElapsedMilliseconds -ge 1000) {
                $shouldUpdate = $true
            }
        }
        if (-not $shouldUpdate) { return }
        $statusContext = $Context
        if ([string]::IsNullOrWhiteSpace($statusContext)) {
            $statusContext = if ($currentSource) { Split-Path -Leaf $currentSource } else { 'input' }
        }
        $status = "Processed {0:N0} hashes (+{1:N0} invalid, {2:N0} skipped, {3:N0} lines) [{4}]" -f $meta.ValidEntries, $meta.InvalidLines, $meta.SkippedLines, $meta.TotalLines, $statusContext
        Write-Progress -Activity $ProgressActivity -Status $status -PercentComplete 0
        if ($EnableCheckpoint -and $plainReader) {
            $checkpointPosition = if ($plainBaseStream) { $plainBaseStream.Position } else { $plainReader.BaseStream.Position }
            & $saveCheckpoint $checkpointPosition
        }
        $progressStopwatch.Restart()
    }

    $processHashLine = {
        param(
            [string]$rawLine,
            [string]$prefix
        )
        if ($null -eq $rawLine) { return }
        $trimmed = $rawLine.Trim()
        if ($trimmed.Length -eq 0) { return }
        if ($trimmed.StartsWith('#')) { return }
        if ($ForcePlainText -and $trimmed -match '(?i)\.gz(\s*)$') {
            $meta.TotalLines++
            $meta.SkippedLines++
            return
        }

        # Fast path for valid 32-char hex lines. Routes through the same pending-line dedup as the
        # slow path below (adjacent identical hashes are dropped) instead of writing straight
        # through - the source is expected to be pre-sorted, so only *adjacent* duplicates are
        # caught either way, but the fast path used to skip this entirely and write every
        # duplicate straight to the shard.
        if ($rawLine.Length -eq 32 -and $rawLine -match '^[0-9A-Fa-f]{32}$') {
            $normalizedHash = $rawLine.ToUpperInvariant()
            $prefixKey = $normalizedHash.Substring(0, $PrefixLength).ToLowerInvariant()
            $state = $shardStates[$prefixKey]
            if ($state.PendingHash -ne $normalizedHash) {
                if ($state.PendingLine) {
                    $state.Writer.WriteLine($state.PendingLine)
                    $state.Count++
                    $meta.ValidEntries++
                }
                $state.PendingLine = $normalizedHash
                $state.PendingHash = $normalizedHash
                $state.PendingCount = 0
            }
            $meta.TotalLines++
            return
        }

        $meta.TotalLines++

        $parts = $trimmed.Split(':', 2)
        $hashPortion = $parts[0].Trim()
        if (-not [string]::IsNullOrWhiteSpace($prefix)) {
            $hashPortion = ($prefix.Trim() + $hashPortion)
        }
        if ($hashPortion.Length -ne 32 -or $hashPortion -notmatch '^[0-9A-Fa-f]{32}$') {
            $match = [regex]::Match($hashPortion, '[0-9A-Fa-f]{32}')
            if ($match.Success) {
                $hashPortion = $match.Value
            }
        }
        if ($hashPortion.Length -ne 32 -or $hashPortion -notmatch '^[0-9A-Fa-f]{32}$') {
            $meta.InvalidLines++
            if ($meta.InvalidSamples.Count -lt $maxInvalidSamples) {
                [void]$meta.InvalidSamples.Add($trimmed)
            }
            & $ensureInvalidWriter
            if ($invalidOutput.Writer) { $invalidOutput.Writer.WriteLine($trimmed) }
            & $invokeProgress $false
            return
        }
        if ($hashPortion.Length -lt $PrefixLength) {
            $meta.InvalidLines++
            if ($meta.InvalidSamples.Count -lt $maxInvalidSamples) {
                [void]$meta.InvalidSamples.Add($trimmed)
            }
            & $ensureInvalidWriter
            if ($invalidOutput.Writer) { $invalidOutput.Writer.WriteLine($trimmed) }
            & $invokeProgress $false
            return
        }
        $normalizedHash = $hashPortion.ToUpperInvariant()
        $countValue = 0
        if ($parts.Count -gt 1) {
            $meta.LegacyLines++
            $countText = $parts[1].Trim()
            if (-not [string]::IsNullOrWhiteSpace($countText)) {
                $null = [int]::TryParse($countText, [ref]$countValue)
                if ($countValue -lt 0) { $countValue = 0 }
            }
        }
        $normalizedLine = $normalizedHash

        $prefixKey = $normalizedHash.Substring(0, $PrefixLength).ToLowerInvariant()
        if (-not $shardStates.ContainsKey($prefixKey)) {
            $shardPath = Join-Path -Path $ShardRoot -ChildPath ("$prefixKey.txt")
            Ensure-Directory (Split-Path -Path $shardPath -Parent)
            $appendExisting = $Resume -and (Test-Path -LiteralPath $shardPath)
            $existingCount = 0L
            if ($appendExisting) {
                try {
                    $countReader = [System.IO.File]::OpenText($shardPath)
                    try {
                        while ($null -ne $countReader.ReadLine()) { $existingCount++ }
                    } finally { $countReader.Dispose() }
                } catch { $existingCount = 0L }
            }
            $writer = New-Object System.IO.StreamWriter($shardPath, $appendExisting, $encoding, 1048576)
            $state = [ordered]@{
                Writer = $writer
                Path = $shardPath
                Count = $existingCount
                PendingLine = $null
                PendingHash = $null
                PendingCount = -1
            }
            $shardStates[$prefixKey] = $state
        }
        $state = $shardStates[$prefixKey]

        if ($state.PendingHash -and $state.PendingHash -eq $normalizedHash) {
            if ($countValue -gt $state.PendingCount) {
                $state.PendingLine = $normalizedLine
                $state.PendingCount = $countValue
            }
        } else {
            if ($state.PendingLine) {
                $state.Writer.WriteLine($state.PendingLine)
                $state.Count++
                $meta.ValidEntries++
            }
            $state.PendingLine = $normalizedLine
            $state.PendingHash = $normalizedHash
            $state.PendingCount = $countValue
        }
        & $invokeProgress $false
    }

    $resolveGzipPath = {
        param([string]$pathValue)
        if ([string]::IsNullOrWhiteSpace($pathValue)) { return $null }
        if (Test-Path -LiteralPath $pathValue) { return (Resolve-Path -LiteralPath $pathValue).ProviderPath }
        if ([System.IO.Path]::IsPathRooted($pathValue)) { throw "Gzip file not found: $pathValue" }
        $candidate = Join-Path -Path $sourceBaseDir -ChildPath $pathValue
        if (Test-Path -LiteralPath $candidate) { return (Resolve-Path -LiteralPath $candidate).ProviderPath }
        $meta.TotalLines++
        $meta.InvalidLines++
        if ($meta.InvalidSamples.Count -lt $maxInvalidSamples) {
            [void]$meta.InvalidSamples.Add($pathValue)
        }
        & $ensureInvalidWriter
        if ($invalidOutput.Writer) { $invalidOutput.Writer.WriteLine($pathValue) }
        & $invokeProgress $true
        return $null
    }

    $processGzipFile = {
        param([string]$gzipPath)
        if ($ForcePlainText) {
            return
        }
        $resolved = & $resolveGzipPath $gzipPath
        if (-not $resolved) { return }
        if ($ShowProgress) { $currentSource = $gzipPath }
        $filePrefix = [System.IO.Path]::GetFileNameWithoutExtension($resolved)
        $fileStream = $null
        $gzipStream = $null
        $reader = $null
        try {
            $fileStream = [System.IO.File]::OpenRead($resolved)
            $gzipStream = New-Object System.IO.Compression.GZipStream($fileStream, [System.IO.Compression.CompressionMode]::Decompress)
            # Wrap in BufferedStream for larger read chunks
            $bufferedStream = New-Object System.IO.BufferedStream($gzipStream, 1048576)
            $reader = New-Object System.IO.StreamReader($bufferedStream, [System.Text.Encoding]::UTF8, $true, 1048576)
            while (($line = $reader.ReadLine()) -ne $null) {
                & $processHashLine $line $filePrefix
            }
        } finally {
            if ($reader) { $reader.Dispose() }
            if ($gzipStream) { $gzipStream.Dispose() }
            if ($fileStream) { $fileStream.Dispose() }
        }
        & $invokeProgress $true $gzipPath
    }

    try {
        if ($sourceItem.PSIsContainer) {
            $gzipFiles = Get-ChildItem -LiteralPath $sourceItem.FullName -Filter '*.gz' -File -Recurse | Sort-Object FullName
            if (-not $gzipFiles) { throw "Source directory '$($sourceItem.FullName)' does not contain any .gz files." }
            foreach ($file in $gzipFiles) {
                & $processGzipFile $file.FullName
            }
        } else {
            if ($ShowProgress) { $currentSource = $sourceItem.FullName }
            $mode = if ($ForcePlainText) { 'Plain' } else { $null }
            # Use BufferedStream for larger read chunks
            $fileStream = [System.IO.File]::Open($sourceItem.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
            if ($Resume -and $resumeFilePosition -gt 0) {
                if ($fileStream.Length -lt $resumeFilePosition) {
                    throw "Checkpoint position $resumeFilePosition exceeds source length $($fileStream.Length)."
                }
                $fileStream.Seek($resumeFilePosition, [System.IO.SeekOrigin]::Begin) | Out-Null
            }
            $bufferedStream = New-Object System.IO.BufferedStream($fileStream, 1048576)
            $reader = New-Object System.IO.StreamReader($bufferedStream, [System.Text.Encoding]::UTF8, $true, 1048576)
            $plainReader = $reader
            $plainBaseStream = $fileStream
            try {
                while (($line = $reader.ReadLine()) -ne $null) {
                    $trimmed = $line.Trim()
                    if ($trimmed.Length -eq 0) { continue }
                    if ($trimmed.StartsWith('#')) { continue }
                    if (-not $mode) {
                        if ($trimmed -like '*.gz') {
                            $resolvedProbe = & $resolveGzipPath $trimmed
                            if ($resolvedProbe) {
                                $mode = 'GzList'
                                if ($ShowProgress) { $currentSource = $trimmed }
                            } else {
                                continue
                            }
                        } else {
                            $mode = 'Plain'
                        }
                    }

                    if ($mode -eq 'Plain') {
                        & $processHashLine $line $null
                    } elseif (-not $ForcePlainText -and $trimmed -like '*.gz') {
                        & $processGzipFile $trimmed
                    } else {
                        if ($ForcePlainText -and $trimmed -match '(?i)\.gz(\s*)$') {
                            $meta.TotalLines++
                            $meta.SkippedLines++
                        } else {
                            $meta.TotalLines++
                            $meta.InvalidLines++
                            if ($meta.InvalidSamples.Count -lt $maxInvalidSamples) {
                                [void]$meta.InvalidSamples.Add($trimmed)
                            }
                            & $ensureInvalidWriter
                            if ($invalidOutput.Writer) { $invalidOutput.Writer.WriteLine($trimmed) }
                        }
                        & $invokeProgress $false
                    }
                }
            } finally {
                if ($reader) { $reader.Dispose() }
                if ($fileStream) { $fileStream.Dispose() }
                $plainReader = $null
                $plainBaseStream = $null
            }
        }
    } finally {
        if ($invalidOutput.Writer) { $invalidOutput.Writer.Dispose() }
    }

    foreach ($entry in ($shardStates.GetEnumerator() | Sort-Object Key)) {
        $prefix = $entry.Key
        $state = $entry.Value
        if ($state.PendingLine) {
            $state.Writer.WriteLine($state.PendingLine)
            $state.Count++
            $meta.ValidEntries++
            $state.PendingLine = $null
        }
        $state.Writer.Dispose()
        $stats[$prefix] = [ordered]@{
            Path = $state.Path
            Count = $state.Count
        }
    }

    if ($meta.ValidEntries -eq 0) { throw 'Source did not contain any valid hashes after processing.' }
    if ($ShowProgress) {
        $status = "Processed {0:N0} hashes (+{1:N0} invalid, {2:N0} skipped, {3:N0} lines)" -f $meta.ValidEntries, $meta.InvalidLines, $meta.SkippedLines, $meta.TotalLines
        Write-Progress -Activity $ProgressActivity -Status $status -Completed
    }
    return [pscustomobject]@{
        TotalEntries = [long]$meta.ValidEntries
        ShardStats   = $stats
        TotalLines   = [long]$meta.TotalLines
        InvalidLines = [long]$meta.InvalidLines
        SkippedLines = [long]$meta.SkippedLines
        LegacyCount = [long]$meta.LegacyLines
        InvalidSamples = $meta.InvalidSamples.ToArray()
        InvalidOutputPath = if ($meta.InvalidLines -gt 0 -and $InvalidOutputPath) { $InvalidOutputPath } else { $null }
    }
}

function Write-JsonFile {
    param(
        [string]$Path,
        [object]$Data
    )

    $json = $Data | ConvertTo-Json -Depth 6
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $json, $encoding)
}

# -- Argument validation ------------------------------------------------------

$resolvedSource = Resolve-Path -LiteralPath $SourcePath -ErrorAction Stop
if (-not (Test-Path -LiteralPath $resolvedSource)) {
    throw "Source file not found at $SourcePath"
}
if (-not $OutputRoot) {
    $OutputRoot = Join-Path -Path (Split-Path -Parent $resolvedSource.Path) -ChildPath 'khdb-package'
}

$manifestObject = $null
$manifestShards = @()
$totalEntries = 0L
$totalLines = 0L
$invalidCount = 0L
$skippedCount = 0L
$totalSizeBytes = 0L
$summaryMessage = $null
$manifestHash = $null
$manifestPath = Join-Path -Path $OutputRoot -ChildPath 'manifest.json'
$localShardRoot = Join-Path -Path $OutputRoot -ChildPath 'shards'
$normalizedShardPrefix = $null

$checkpointEnabled = $false
$resume = $false
$resumeState = $null
$resolvedCheckpointPath = $null

if (-not $NoCheckpoint) {
    if (-not $ForcePlainText) {
        Write-Warning 'Checkpointing is only available with -ForcePlainText; continuing without checkpoints.'
    } else {
        if (-not $CheckpointPath) {
            $CheckpointPath = Join-Path -Path $OutputRoot -ChildPath 'khdb.checkpoint.json'
        }
        $resolvedCheckpointPath = [System.IO.Path]::GetFullPath($CheckpointPath)
        $checkpointDirectory = Split-Path -Path $resolvedCheckpointPath -Parent
        if ($checkpointDirectory -and -not (Test-Path -LiteralPath $checkpointDirectory)) {
            [System.IO.Directory]::CreateDirectory($checkpointDirectory) | Out-Null
        }
        if (Test-Path -LiteralPath $resolvedCheckpointPath) {
            try {
                $resumeState = (Get-Content -LiteralPath $resolvedCheckpointPath -Encoding UTF8 -Raw) | ConvertFrom-Json
            } catch {
                throw "Failed to parse checkpoint '$resolvedCheckpointPath': $($_.Exception.Message)"
            }
            if (-not $resumeState) { throw "Checkpoint '$resolvedCheckpointPath' is empty or invalid." }
            if ($resumeState.version -and $resumeState.version -ne 1) { throw "Unsupported checkpoint version $($resumeState.version)." }
            $resume = $true
        }
        $checkpointEnabled = $true
    }
}

if ($resume -and $resumeState -and $resumeState.sourcePath) {
    $resumeSourcePath = [System.IO.Path]::GetFullPath([string]$resumeState.sourcePath)
    if ($resumeSourcePath -ne $resolvedSource.Path) {
        throw "Checkpoint source '$resumeSourcePath' does not match current source '$($resolvedSource.Path)'."
    }
}

if (Test-Path -LiteralPath $OutputRoot) {
    $startingFresh = -not $resume
    if ($startingFresh) {
        if (-not $Force) {
            $existing = Get-ChildItem -LiteralPath $OutputRoot -Force | Select-Object -First 1
            if ($existing) {
                throw "Output root '$OutputRoot' already exists and is not empty. Use -Force to overwrite."
            }
        } else {
            Remove-DirectoryContents -Path $OutputRoot
        }
    }
} else {
    Ensure-Directory $OutputRoot
}

Ensure-Directory $localShardRoot

$invalidReportPath = Join-Path -Path $OutputRoot -ChildPath 'invalid-hashes.txt'
if (-not $resume -and (Test-Path -LiteralPath $invalidReportPath)) { Remove-Item -LiteralPath $invalidReportPath -Force }

Write-Host "Splitting '$($resolvedSource.Path)' into shard prefix length $ShardSize..."
$splitResult = Split-KhdbIntoShards -Source $resolvedSource.Path -ShardRoot $localShardRoot -PrefixLength $ShardSize -InvalidOutputPath $invalidReportPath -ShowProgress:$ShowProgress -ProgressUpdateInterval $ProgressUpdateInterval -ProgressActivity 'Preparing KHDB shards' -ForcePlainText:$ForcePlainText -EnableCheckpoint:$checkpointEnabled -CheckpointPath $resolvedCheckpointPath -Resume:$resume -ResumeState $resumeState
$totalEntries = [long]$splitResult.TotalEntries
$totalLines = [long]$splitResult.TotalLines
$invalidCount = [long]$splitResult.InvalidLines
$skippedCount = [long]$splitResult.SkippedLines
Write-Host ("Input summary: {0} non-empty line(s) -> {1} valid hash(es), {2} invalid entr(y/ies), {3} skipped." -f $totalLines, $totalEntries, $invalidCount, $skippedCount)
if ([long]$splitResult.LegacyCount -gt 0) {
    Write-Warning ("Detected {0} legacy HASH:count entries. Output shards and khdb-clean.txt were normalized to hash-only lines for DSInternals compatibility." -f [long]$splitResult.LegacyCount)
}
if ($invalidCount -gt 0) {
    if ($splitResult.InvalidOutputPath) {
        Write-Warning ("Invalid lines saved to {0}" -f $splitResult.InvalidOutputPath)
    }
    if ($splitResult.InvalidSamples -and $splitResult.InvalidSamples.Count -gt 0) {
        Write-Warning "Sample invalid lines:"
        foreach ($sample in $splitResult.InvalidSamples) {
            Write-Warning ("  {0}" -f $sample)
        }
    }
} elseif (-not $resume -and (Test-Path -LiteralPath $invalidReportPath)) {
    Remove-Item -LiteralPath $invalidReportPath -Force
}

$manifestShards = @()
$totalSizeBytes = 0L

foreach ($prefix in ($splitResult.ShardStats.Keys | Sort-Object)) {
    $info = $splitResult.ShardStats[$prefix]
    $fileInfo = Get-Item -LiteralPath $info.Path
    $totalSizeBytes += $fileInfo.Length
    $hash = (Get-FileHash -Path $info.Path -Algorithm SHA256).Hash.ToLowerInvariant()
    $manifestShards += [pscustomobject]@{
        name    = "$prefix.txt"
        prefix  = $prefix
        entries = $info.Count
        size    = [string]$fileInfo.Length
        sha256  = $hash
    }
}

$manifestVersionValue = if ([string]::IsNullOrWhiteSpace($ManifestVersion)) {
    (Get-Date).ToString('yyyyMMdd-HHmmss')
} else {
    $ManifestVersion
}

$normalizedShardPrefix = Get-NormalizedForwardPath -PathValue $ShardRemotePrefix
$manifestObject = [ordered]@{
    version        = $manifestVersionValue
    generatedAt    = (Get-Date).ToUniversalTime().ToString('o')
    shardSize      = $ShardSize
    shardPrefix    = $normalizedShardPrefix
    totalEntries   = $totalEntries
    inputLines     = $totalLines
    invalidEntries = $invalidCount
    skippedEntries = $skippedCount
    totalShards    = $manifestShards.Count
    totalSize      = [string]$totalSizeBytes
    shards         = $manifestShards
}

Write-Host ("Writing manifest to {0}" -f $manifestPath)
Write-JsonFile -Path $manifestPath -Data $manifestObject
$manifestHash = (Get-FileHash -Path $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()

Write-Host ("Manifest SHA256: {0}" -f $manifestHash)
$cleanCombinedPath = Join-Path -Path $OutputRoot -ChildPath 'khdb-clean.txt'
Write-Host ("Writing cleaned aggregate to {0}..." -f $cleanCombinedPath)
Merge-ShardsToFile -Manifest $manifestObject -ShardsRoot $localShardRoot -TargetPath $cleanCombinedPath
$cleanHash = (Get-FileHash -Path $cleanCombinedPath -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Host ("Clean KHDB SHA256: {0}" -f $cleanHash)
$summaryMessage = ("Summary: {0} shards, {1} valid hashes, {2} invalid entries, {3} skipped, {4:N0} bytes." -f $manifestShards.Count, $totalEntries, $invalidCount, $skippedCount, $totalSizeBytes)

Write-Host $summaryMessage
Write-Host ("Package ready under '{0}'. Upload the shards to '{1}/', then manifest.json last." -f $OutputRoot, $normalizedShardPrefix)

if ($checkpointEnabled -and $resolvedCheckpointPath -and (Test-Path -LiteralPath $resolvedCheckpointPath)) {
    Remove-Item -LiteralPath $resolvedCheckpointPath -Force
}
