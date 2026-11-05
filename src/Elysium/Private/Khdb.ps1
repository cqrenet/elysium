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
        # Shard names are joined onto local paths. A tampered manifest must not be able to place files
        # outside the shard directory (e.g. over Elysium's own scripts on an admin host).
        if ([System.IO.Path]::IsPathRooted($name) -or $name.Contains(':') -or @($name -split '[\\/]') -contains '..') {
            throw "Manifest shard name '$name' is not a plain relative path inside the shard directory."
        }
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

function Merge-ShardsToFile {
    # Concatenates the manifest's shards (by name, which is prefix order) into one sorted, de-duplicated
    # KHDB file, using the compiled KhdbMerger from KhdbMerge.ps1.
    param(
        [psobject]$Manifest,
        [string]$ShardsRoot,
        [string]$TargetPath
    )

    $shards = @($Manifest.shards | Sort-Object name)
    $merger = [Elysium.KhdbMerger]::new($TargetPath)
    try {
        $index = 0
        foreach ($entry in $shards) {
            $index++
            $relative = [string]$entry.name
            $shardPath = Join-Path -Path $ShardsRoot -ChildPath $relative
            if (-not (Test-Path -LiteralPath $shardPath)) {
                throw "Missing shard on disk: $relative"
            }
            Write-Progress -Activity 'Building combined KHDB' -Status ("{0}/{1} shards, {2:N0} hashes" -f $index, $shards.Count, $merger.Written) -PercentComplete (100 * $index / $shards.Count)
            $merger.AddShard($shardPath, $relative)
        }
        Write-Progress -Activity 'Building combined KHDB' -Completed
        Write-Host ("Combined KHDB: {0:N0} hash(es), {1:N0} duplicate(s) removed." -f $merger.Written, $merger.Duplicates)
    } finally {
        $merger.Dispose()
    }
}

function Validate-KHDBFile {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { throw "Validation failed: $Path not found." }

    $duplicates = [long]0
    $outOfOrder = [long]0
    $count = [Elysium.KhdbText]::Validate($Path, [ref]$duplicates, [ref]$outOfOrder)

    if ($count -eq 0) { throw 'Validation failed: KHDB file is empty.' }
    if ($outOfOrder -gt 0) {
        Write-Warning ("Validation warning: {0} line(s) out of order." -f $outOfOrder)
    }
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

function Receive-KhdbShard {
    # Runs in an Invoke-InModuleRunspace worker: download one shard to staging, check size and SHA-256
    # against its manifest entry, then move it into the local shard directory.
    param(
        [Parameter(Mandatory)][hashtable]$Storage,
        [string]$RemotePrefix,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Sha256,
        [Parameter(Mandatory)][long]$Size,
        [Parameter(Mandatory)][string]$StagingRoot,
        [Parameter(Mandatory)][string]$ShardRoot
    )

    $stagingPath = Join-Path -Path $StagingRoot -ChildPath $Name
    Ensure-Directory (Split-Path -Path $stagingPath -Parent)
    Invoke-StorageDownload -Storage $Storage -Key (Combine-StoragePath -Prefix $RemotePrefix -Name $Name) -TargetPath $stagingPath

    $actualSize = (Get-Item -LiteralPath $stagingPath).Length
    if ($actualSize -ne $Size) { throw "Shard '$Name' size mismatch. Expected $Size bytes, got $actualSize." }
    $actualHash = Get-FileSha256Lower -Path $stagingPath
    if ($actualHash -ne $Sha256) { throw "Shard '$Name' checksum mismatch. Expected $Sha256, got $actualHash." }

    $finalPath = Join-Path -Path $ShardRoot -ChildPath $Name
    Ensure-Directory (Split-Path -Path $finalPath -Parent)
    Move-Item -LiteralPath $stagingPath -Destination $finalPath -Force
    Write-Host ("Shard '{0}' updated." -f $Name)
}
