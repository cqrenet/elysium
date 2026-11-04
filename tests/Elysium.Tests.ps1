# Pester 5 tests for the module's helpers. Run: Invoke-Pester ./tests
# AD-dependent helpers (AdPreflight.ps1) need a domain and are not covered here.

BeforeAll {
    foreach ($file in Get-ChildItem -Path (Join-Path $PSScriptRoot '../src/Elysium/Private') -Filter '*.ps1') {
        . $file.FullName
    }
}

Describe 'Settings parsing' {
    It 'parses keys, strips single quotes, keeps "=" inside values, skips comments and junk' {
        $path = Join-Path $TestDrive 'settings.txt'
        Set-Content -LiteralPath $path -Value @(
            '# comment'
            ''
            '  StorageProvider = S3  '
            "s3Region='eu-central-1'"
            'sasToken=sv=2022-11-02&sig=abc%3D=='
            'not a setting'
        )
        $settings = Read-KeyValueSettingsFile -Path $path
        $settings.Count | Should -Be 3
        $settings['StorageProvider'] | Should -Be 'S3'
        $settings['s3Region'] | Should -Be 'eu-central-1'
        $settings['sasToken'] | Should -Be 'sv=2022-11-02&sig=abc%3D=='
    }

    It 'returns an empty table for a missing file, but Read-ElysiumSettings throws' {
        (Read-KeyValueSettingsFile -Path (Join-Path $TestDrive 'missing.txt')).Count | Should -Be 0
        { Read-ElysiumSettings -ScriptRoot $TestDrive } | Should -Throw '*Settings file not found*'
    }
}

Describe 'Storage paths and URIs' {
    It 'joins prefix and name with single forward slashes' {
        Combine-StoragePath -Prefix '/khdb/shards/' -Name '\00.txt' | Should -Be 'khdb/shards/00.txt'
        Combine-StoragePath -Prefix $null -Name 'a\b.txt' | Should -Be 'a/b.txt'
    }

    It 'builds the same Azure blob URI with or without a leading "?" on the SAS, keeping its escaping' {
        $expected = 'https://acct.blob.core.windows.net/khdb/khdb/manifest.json?sv=2022-11-02&sig=abc%3D'
        Build-BlobUri -Account acct -Container khdb -Sas 'sv=2022-11-02&sig=abc%3D' -BlobName 'khdb\manifest.json' | Should -Be $expected
        Build-BlobUri -Account acct -Container khdb -Sas '?sv=2022-11-02&sig=abc%3D' -BlobName '/khdb/manifest.json' | Should -Be $expected
    }

    It 'refuses an empty SAS token' {
        { Build-BlobUri -Account acct -Container khdb -Sas ' ' -BlobName x } | Should -Throw '*sasToken*'
    }

    It 'builds path-style and virtual-host S3 URIs' {
        (BuildS3Uri 'https://s3.example.com' 'khdb-bucket' 'khdb/manifest.json' $true).AbsoluteUri |
            Should -Be 'https://s3.example.com/khdb-bucket/khdb/manifest.json'
        (BuildS3Uri 'https://minio.example.com:9000' 'khdb-bucket' '/uploads/x.enc' $false).AbsoluteUri |
            Should -Be 'https://khdb-bucket.minio.example.com:9000/uploads/x.enc'
    }
}

Describe 'SigV4 signing' {
    # Expected Authorization values were generated with botocore 1.43 (S3SigV4Auth) from the same
    # request, credentials and timestamp - an independent implementation, not hand-computed.
    BeforeAll {
        Mock Get-Date { [datetime]::new(2026, 1, 2, 3, 4, 5, [DateTimeKind]::Utc) }
        $accessKey = 'AKIDEXAMPLE'
        $secretKey = 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY'
    }

    It 'signs a path-style GET with an empty payload' {
        $uri = BuildS3Uri 'https://s3.example.com' 'khdb-bucket' 'khdb/manifest.json' $true
        $headers = BuildAuthHeaders 'GET' $uri 'eu-central-1' $accessKey $secretKey (Get-HashHex (Get-Bytes ''))
        $headers['x-amz-date'] | Should -Be '20260102T030405Z'
        $headers['x-amz-content-sha256'] | Should -Be 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
        $headers['Authorization'] | Should -Be 'AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260102/eu-central-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=b131e4156268eeaac455af7956b3ad168cdc834006b2b0441416ef5a11570b26'
    }

    It 'signs a virtual-host PUT on a non-default port' {
        $uri = BuildS3Uri 'https://minio.example.com:9000' 'khdb-bucket' 'uploads/CONTOSO_NTLM_Hashes_20260102-030405.enc' $false
        $headers = BuildAuthHeaders 'PUT' $uri 'us-east-1' $accessKey $secretKey (Get-HashHex (Get-Bytes 'hello'))
        $headers['Authorization'] | Should -Be 'AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260102/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=b1d680a2dae687024f8b81a6792cf886857f30fef62865f65838bd06e70238fe'
    }
}

Describe 'KHDB manifest and merge' {
    It 'rejects duplicate shard names, bad checksums and an out-of-range shardSize' {
        $ok = { param($name) [pscustomobject]@{ name = $name; sha256 = ('a' * 64); size = 1 } }
        { Validate-Manifest ([pscustomobject]@{ shardSize = 4; shards = @((& $ok '00.txt'), (& $ok '01.txt')) }) } | Should -Not -Throw
        { Validate-Manifest ([pscustomobject]@{ shards = @((& $ok '00.txt'), (& $ok '00.txt')) }) } | Should -Throw '*duplicate*'
        { Validate-Manifest ([pscustomobject]@{ shards = @([pscustomobject]@{ name = '00.txt'; sha256 = 'abc'; size = 1 }) }) } | Should -Throw '*sha256*'
        { Validate-Manifest ([pscustomobject]@{ shardSize = 9; shards = @((& $ok '00.txt')) }) } | Should -Throw '*shardSize*'
    }

    It 'throws when shards would merge out of order' {
        Set-Content -LiteralPath (Join-Path $TestDrive '00.txt') -Value ('F' * 32)
        Set-Content -LiteralPath (Join-Path $TestDrive '01.txt') -Value ('0' * 32)
        $manifest = [pscustomobject]@{ shards = @([pscustomobject]@{ name = '00.txt' }, [pscustomobject]@{ name = '01.txt' }) }
        { Merge-ShardsToFile -Manifest $manifest -ShardsRoot $TestDrive -TargetPath (Join-Path $TestDrive 'out.txt') } | Should -Throw '*unsorted*'
    }

    It 'rejects an empty KHDB file' {
        Set-Content -LiteralPath (Join-Path $TestDrive 'empty.txt') -Value @()
        { Validate-KHDBFile -Path (Join-Path $TestDrive 'empty.txt') } | Should -Throw '*empty*'
    }
}

Describe 'Update-ElysiumKhdb (incremental sync against a fake Azure container)' {
    BeforeAll {
        Import-Module (Join-Path $PSScriptRoot '../src/Elysium/Elysium.psd1') -Force
        $root = Join-Path $TestDrive 'install'
        $remote = Join-Path $TestDrive 'remote'
        New-Item -ItemType Directory -Path $root, (Join-Path $remote 'khdb/shards') -Force | Out-Null
        & (Get-Module Elysium) { param($r) $script:InstallRoot = $r } $root
        Set-Content -LiteralPath (Join-Path $root 'ElysiumSettings.txt') -Value @(
            'storageAccountName=acct', 'containerName=khdb', 'sasToken=sv=2022-11-02&sig=x')

        # Serves blob URIs from $remote: https://acct.blob.core.windows.net/khdb/<blob>?sas -> $remote/<blob>.
        # Pester runs the mock body in this scope, so $remote and the mocked call's $Uri/$TargetPath
        # are both visible (a .GetNewClosure() here would hide them).
        Mock -ModuleName Elysium Invoke-DownloadWithRetry {
            $blob = ([uri]$Uri).AbsolutePath -replace '^/khdb/', ''
            Copy-Item -LiteralPath (Join-Path $remote $blob) -Destination $TargetPath
        }

        function Publish-Shards([hashtable]$Shards) {
            $entries = foreach ($name in $Shards.Keys | Sort-Object) {
                $path = Join-Path $remote "khdb/shards/$name"
                Set-Content -LiteralPath $path -Value $Shards[$name]
                [ordered]@{ name = $name; sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant(); size = (Get-Item -LiteralPath $path).Length }
            }
            # Same top-level fields Prepare-KHDBStorage.ps1 always writes; the updater runs under
            # StrictMode, so version/shardSize/shardPrefix are effectively required.
            @{ version = '1'; shardSize = 2; shardPrefix = 'khdb/shards'; shards = @($entries) } |
                ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $remote 'khdb/manifest.json')
        }
        $khdb = Join-Path $root 'khdb.txt'
    }

    It 'downloads everything on first run, normalizing case and HASH:count and merging in order' {
        Publish-Shards @{
            '00.txt' = @('00112233445566778899AABBCCDDEEFF', '00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF')
            'ab.txt' = @('ab112233445566778899aabbccddeeff:12', 'ABFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF')
        }
        Update-ElysiumKhdb -MaxParallelTransfers 1 6>$null
        Get-Content -LiteralPath $khdb | Should -Be @(
            '00112233445566778899AABBCCDDEEFF', '00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
            'AB112233445566778899AABBCCDDEEFF', 'ABFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF')
        Should -Invoke Invoke-DownloadWithRetry -ModuleName Elysium -Times 3 -Exactly   # manifest + 2 shards
    }

    It 'downloads only the manifest when nothing changed' {
        Update-ElysiumKhdb -MaxParallelTransfers 1 6>$null
        Should -Invoke Invoke-DownloadWithRetry -ModuleName Elysium -Times 1 -Exactly
    }

    It 'downloads only the changed shard and removes shards the manifest no longer lists' {
        $stale = Join-Path $root 'khdb-shards/zz.txt'
        Set-Content -LiteralPath $stale -Value ('Z' * 32)
        Publish-Shards @{
            '00.txt' = @('00112233445566778899AABBCCDDEEFF', '00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF')
            'ab.txt' = @('ABFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF')
        }
        Update-ElysiumKhdb -MaxParallelTransfers 1 6>$null
        Should -Invoke Invoke-DownloadWithRetry -ModuleName Elysium -Times 2 -Exactly   # manifest + ab.txt
        Test-Path -LiteralPath $stale | Should -BeFalse
        Get-Content -LiteralPath $khdb | Should -Be @(
            '00112233445566778899AABBCCDDEEFF', '00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF', 'ABFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF')
    }
}

Describe 'Update-ElysiumLithnetStore' {
    BeforeAll {
        Import-Module (Join-Path $PSScriptRoot '../src/Elysium/Elysium.psd1') -Force
        # Stand-ins for the LithnetPasswordProtection cmdlets, so they can be mocked on any OS.
        $lithnetCommands = 'Open-Store', 'Close-Store', 'Sync-HashesFromHibp', 'Import-CompromisedPasswordHashes', 'Import-CompromisedPasswords', 'Import-BannedWords'
        foreach ($name in $lithnetCommands) { New-Item -Path "function:global:$name" -Value { param($Path, $Filename) } -Force | Out-Null }

        $root = Join-Path $TestDrive 'lithnet'
        New-Item -ItemType Directory -Path (Join-Path $root 'store'), (Join-Path $root 'data') -Force | Out-Null
        & (Get-Module Elysium) { param($r) $script:InstallRoot = $r } $root
        $khdb = Join-Path $root 'data/custom.txt'
        $plain = Join-Path $root 'plain.txt'
        $banned = Join-Path $root 'banned.txt'
        Set-Content -LiteralPath $khdb, $plain, $banned -Value 'x'
        Set-Content -LiteralPath (Join-Path $root 'ElysiumSettings.txt') -Value @(
            "LithnetStorePath=$(Join-Path $root 'store')"
            'InstallationPath=data'
            'WeakPasswordsDatabase=custom.txt'
            "LithnetPlaintextSources=$plain"
            'LithnetSyncHibp=true')
    }

    BeforeEach {
        foreach ($name in $lithnetCommands) { Mock -ModuleName Elysium $name {} }
        Mock -ModuleName Elysium Import-Module {} -ParameterFilter { $Name -contains 'LithnetPasswordProtection' }
    }

    AfterAll {
        foreach ($name in $lithnetCommands) { Remove-Item -Path "function:global:$name" -ErrorAction SilentlyContinue }
    }

    It 'imports the configured KHDB by default, merges settings and parameter sources, and syncs HIBP' {
        Update-ElysiumLithnetStore -BannedWordFiles $banned 6>$null
        Should -Invoke Import-CompromisedPasswordHashes -ModuleName Elysium -Times 1 -Exactly -ParameterFilter { $Filename -eq (Resolve-Path -LiteralPath $khdb).Path }
        Should -Invoke Import-CompromisedPasswords -ModuleName Elysium -Times 1 -Exactly -ParameterFilter { $Filename -eq (Resolve-Path -LiteralPath $plain).Path }
        Should -Invoke Import-BannedWords -ModuleName Elysium -Times 1 -Exactly -ParameterFilter { $Filename -eq (Resolve-Path -LiteralPath $banned).Path }
        Should -Invoke Sync-HashesFromHibp -ModuleName Elysium -Times 1 -Exactly
        Should -Invoke Close-Store -ModuleName Elysium -Times 1 -Exactly
    }

    It 'skips the HIBP sync with -SkipHibpSync' {
        Update-ElysiumLithnetStore -SkipHibpSync 6>$null
        Should -Invoke Sync-HashesFromHibp -ModuleName Elysium -Times 0 -Exactly
    }

    It 'closes the store even when an import fails' {
        Mock -ModuleName Elysium Import-CompromisedPasswords { throw 'import failed' }
        { Update-ElysiumLithnetStore -SkipHibpSync 6>$null } | Should -Throw '*import failed*'
        Should -Invoke Close-Store -ModuleName Elysium -Times 1 -Exactly
    }

    It 'names the KHDB path it looked for when it is missing' {
        Remove-Item -LiteralPath $khdb
        { Update-ElysiumLithnetStore -SkipHibpSync 6>$null } | Should -Throw "*KHDB was not found at '$khdb'*"
    }
}

Describe 'Password-quality helpers' {
    It 'lists DomainNName/DomainNDC pairs in order and stops at the first gap' {
        $domains = Get-DomainDetailsFromSettings -Settings @{
            Domain1Name = 'contoso.local'; Domain1DC = 'dc1.contoso.local'
            Domain2Name = 'fabrikam.local'; Domain2DC = 'dc1.fabrikam.local'
            Domain4Name = 'unreachable.local'; Domain4DC = 'dc'
        }
        @($domains.Keys) | Should -Be @('1', '2')
        $domains['2'].Name | Should -Be 'fabrikam.local'
        $domains['2'].DC | Should -Be 'dc1.fabrikam.local'
    }

    It 'hands DSInternals an already clean KHDB unchanged' {
        $path = Join-Path $TestDrive 'clean.txt'
        Set-Content -LiteralPath $path -Value @(('0' * 32), ('A' * 32))
        $resolved = Resolve-DSInternalsWeakHashFile -Path $path
        $resolved.Path | Should -Be $path
        $resolved.IsTemporary | Should -BeFalse
    }

    It 'normalizes case, HASH:count suffixes and duplicates into a temporary file' {
        $path = Join-Path $TestDrive 'legacy.txt'
        Set-Content -LiteralPath $path -Value @(('0' * 32), ('a' * 32 + ':7'), ('A' * 32))
        $resolved = Resolve-DSInternalsWeakHashFile -Path $path 3>$null
        try {
            $resolved.IsTemporary | Should -BeTrue
            Get-Content -LiteralPath $resolved.Path | Should -Be @(('0' * 32), ('A' * 32))
        } finally {
            Remove-Item -LiteralPath $resolved.Path -ErrorAction SilentlyContinue
        }
    }

    It 'rejects unsorted and malformed KHDB files' {
        $unsorted = Join-Path $TestDrive 'unsorted.txt'
        Set-Content -LiteralPath $unsorted -Value @(('B' * 32), ('A' * 32))
        { Resolve-DSInternalsWeakHashFile -Path $unsorted } | Should -Throw '*not sorted*'
        $malformed = Join-Path $TestDrive 'malformed.txt'
        Set-Content -LiteralPath $malformed -Value 'not-a-hash'
        { Resolve-DSInternalsWeakHashFile -Path $malformed } | Should -Throw '*invalid content at line 1*'
    }
}
