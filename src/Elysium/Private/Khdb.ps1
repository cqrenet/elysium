# KHDB manifest, shard merge and validation helpers.

function Get-InstallationPath([hashtable]$settings) {
    $p = $settings['InstallationPath']
    if ([string]::IsNullOrWhiteSpace($p)) { return $InstallRoot }
    if ([System.IO.Path]::IsPathRooted($p)) { return $p }
    return (Join-Path -Path $InstallRoot -ChildPath $p)
}

function Get-FileSha256Lower {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "File not found: $Path" }
    return (Get-FileHash -Path $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Ensure-Directory {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }
}

function Get-RelativePath {
    param(
        [string]$BasePath,
        [string]$FullPath
    )

    $base = (Resolve-Path -LiteralPath $BasePath).ProviderPath
    $full = (Resolve-Path -LiteralPath $FullPath).ProviderPath
    if (-not $base.EndsWith([System.IO.Path]::DirectorySeparatorChar)) {
        $base = $base + [System.IO.Path]::DirectorySeparatorChar
    }

    $baseUri = New-Object System.Uri($base, [System.UriKind]::Absolute)
    $fullUri = New-Object System.Uri($full, [System.UriKind]::Absolute)
    $relativeUri = $baseUri.MakeRelativeUri($fullUri)
    $relativePath = [System.Uri]::UnescapeDataString($relativeUri.ToString())
    return $relativePath.Replace('/', [System.IO.Path]::DirectorySeparatorChar)
}

function Load-Manifest {
    param([string]$Path)
    $raw = Get-Content -LiteralPath $Path -Encoding UTF8 -Raw
    return $raw | ConvertFrom-Json
}

function Validate-Manifest {
    param([psobject]$Manifest)

    if (-not $Manifest) { throw 'Manifest is empty or invalid JSON.' }
    if (-not $Manifest.shards) { throw 'Manifest does not contain a shards collection.' }

    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $Manifest.shards) {
        if (-not $entry) { throw 'Manifest contains null shard entries.' }
        $name = [string]$entry.name
        if ([string]::IsNullOrWhiteSpace($name)) { throw 'Manifest shard entry is missing name.' }
        $hash = [string]$entry.sha256
        if ([string]::IsNullOrWhiteSpace($hash) -or $hash.Length -ne 64) { throw "Manifest shard '$name' is missing a valid sha256." }
        $sizeValue = [string]$entry.size
        $sizeParsed = 0L
        if (-not [long]::TryParse($sizeValue, [ref]$sizeParsed) -or $sizeParsed -lt 0) {
            throw "Manifest shard '$name' has invalid size."
        }
        if (-not $seen.Add($name)) { throw "Manifest contains duplicate shard name '$name'." }
    }

    # Merge-ShardsToFile reads shard files purely by name/content and doesn't use shardSize for
    # anything structural, so any prefix length Prepare-KHDBStorage.ps1 can produce (1-8, see its
    # -ShardSize ValidateRange) is fine here - only reject something outside that supported range.
    if ($Manifest.shardSize -and ([int]$Manifest.shardSize -lt 1 -or [int]$Manifest.shardSize -gt 8)) {
        throw "Manifest shardSize $($Manifest.shardSize) is out of the supported range (1-8)."
    }
}

function Convert-KHDBLineToHash {
    param(
        [Parameter(Mandatory)][string]$Line,
        [string]$SourceName,
        [int]$LineNumber
    )

    $trimmed = $Line.Trim()
    if ($trimmed.Length -eq 0) { return $null }
    if ($trimmed -notmatch '^[0-9A-Fa-f]{32}(:\d+)?$') {
        throw ("Invalid KHDB content in '{0}' at line {1}: '{2}'." -f $SourceName, $LineNumber, $trimmed)
    }

    return ($trimmed.Split(':', 2)[0]).ToUpperInvariant()
}

function Merge-ShardsToFile {
    param(
        [psobject]$Manifest,
        [string]$ShardsRoot,
        [string]$TargetPath
    )

    $encoding = New-Object System.Text.UTF8Encoding($false)
    $writer = New-Object System.IO.StreamWriter($TargetPath, $false, $encoding)
    $previousHash = $null
    try {
        foreach ($entry in ($Manifest.shards | Sort-Object name)) {
            $relative = [string]$entry.name
            $shardPath = Join-Path -Path $ShardsRoot -ChildPath $relative
            if (-not (Test-Path -LiteralPath $shardPath)) {
                throw "Missing shard on disk: $relative"
            }
            $reader = New-Object System.IO.StreamReader($shardPath, [System.Text.Encoding]::UTF8, $true)
            $lineNumber = 0
            try {
                while (($line = $reader.ReadLine()) -ne $null) {
                    $lineNumber++
                    $normalizedHash = Convert-KHDBLineToHash -Line $line -SourceName $relative -LineNumber $lineNumber
                    if ($null -eq $normalizedHash) { continue }
                    if ($previousHash -and $normalizedHash -lt $previousHash) {
                        throw "Shard merge would produce an unsorted KHDB file at '$relative' line $lineNumber."
                    }
                    if ($normalizedHash -eq $previousHash) { continue }
                    $writer.WriteLine($normalizedHash)
                    $previousHash = $normalizedHash
                }
            } finally {
                $reader.Dispose()
            }
        }
    } finally {
        $writer.Dispose()
    }
}

function Validate-KHDBFile {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { throw "Validation failed: $Path not found." }

    $regex = '^[0-9A-Fa-f]{32}$'
    $lineNumber = 0
    $previous = $null
    $duplicates = 0
    $reader = New-Object System.IO.StreamReader($Path, [System.Text.Encoding]::UTF8, $true)
    try {
        while (($line = $reader.ReadLine()) -ne $null) {
            $lineNumber++
            $trimmed = $line.Trim()
            if ($trimmed.Length -eq 0) { continue }
            if ($trimmed -notmatch $regex) {
                throw "Validation failed: unexpected format at line $lineNumber ('$trimmed')."
            }
            $normalized = $trimmed.ToUpperInvariant()
            if ($previous -and $normalized -lt $previous) {
                Write-Warning ("Validation warning: line {0} is out of order." -f $lineNumber)
            }
            if ($normalized -eq $previous) { $duplicates++ }
            $previous = $normalized
        }
    } finally {
        $reader.Dispose()
    }

    if ($lineNumber -eq 0) { throw 'Validation failed: KHDB file is empty.' }
    if ($duplicates -gt 0) {
        Write-Warning ("Validation warning: detected {0} duplicate hash entries (file remains unchanged)." -f $duplicates)
    }
}

function Remove-EmptyDirectories {
    param([string]$Root)

    if (-not (Test-Path -LiteralPath $Root)) { return }
    Get-ChildItem -LiteralPath $Root -Directory -Recurse | Sort-Object FullName -Descending | ForEach-Object {
        $childItems = Get-ChildItem -LiteralPath $_.FullName -Force
        if (-not $childItems) {
            Remove-Item -LiteralPath $_.FullName -Force
        }
    }
}

function Get-KhdbPath([hashtable]$settings) {
    $khdbName = if ([string]::IsNullOrWhiteSpace($settings['WeakPasswordsDatabase'])) { 'khdb.txt' } else { $settings['WeakPasswordsDatabase'] }
    return (Join-Path -Path (Get-InstallationPath $settings) -ChildPath $khdbName)
}
