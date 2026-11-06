# Pester 5 tests for the module's helpers. Run: Invoke-Pester ./tests
# AD-dependent helpers (AdPreflight.ps1) need a domain and are not covered here.

BeforeAll {
    foreach ($file in Get-ChildItem -Path (Join-Path $PSScriptRoot '../src/Elysium/Private') -Filter '*.ps1') {
        . $file.FullName
    }
    . (Join-Path $PSScriptRoot 'FakeStorage.ps1')
    $ElysiumVersion = 'test'   # module-level in production; the dot-sourced helpers read it

    function New-S3Settings([string]$EndpointUrl) {
        @{ StorageProvider = 'S3'; s3EndpointUrl = $EndpointUrl; s3BucketName = 'bucket'; s3AccessKeyId = 'AKIDEXAMPLE'; s3SecretAccessKey = 'secret' }
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
        foreach ($name in '../x.txt', '..\x.txt', 'a/../../x.txt', '/etc/x.txt', 'C:x.txt', '00.txt:stream') {
            { Validate-Manifest ([pscustomobject]@{ shards = @((& $ok $name)) }) } | Should -Throw '*not a plain relative path*'
        }
        { Validate-Manifest ([pscustomobject]@{ shards = @((& $ok 'sub/00.txt')) }) } | Should -Not -Throw
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

Describe 'Update-ElysiumKhdb (incremental sync against a fake S3 store)' {
    BeforeAll {
        Import-Module (Join-Path $PSScriptRoot '../src/Elysium/Elysium.psd1') -Force
        $root = Join-Path $TestDrive 'install'
        $remote = Join-Path $TestDrive 'remote'
        New-Item -ItemType Directory -Path $root, (Join-Path $remote 'bucket/khdb/shards') -Force | Out-Null
        & (Get-Module Elysium) { param($r) $script:InstallRoot = $r } $root
        $server = Start-FakeStorage -Root $remote
        Set-Content -LiteralPath (Join-Path $root 'ElysiumSettings.txt') -Value ((New-S3Settings $server.Url).GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" })

        function Publish-Shards([hashtable]$Shards) {
            $entries = foreach ($name in $Shards.Keys | Sort-Object) {
                $path = Join-Path $remote "bucket/khdb/shards/$name"
                Set-Content -LiteralPath $path -Value $Shards[$name]
                [ordered]@{ name = $name; sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant(); size = (Get-Item -LiteralPath $path).Length }
            }
            # Same top-level fields tools/Prepare-KHDBStorage.ps1 always writes; the updater runs under
            # StrictMode, so version/shardSize/shardPrefix are effectively required.
            @{ version = '1'; shardSize = 2; shardPrefix = 'khdb/shards'; shards = @($entries) } |
                ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $remote 'bucket/khdb/manifest.json')
        }
        function Get-Downloads { @(Get-FakeStorageLog $server | Where-Object { $_ -like 'GET *' }) }
        $khdb = Join-Path $root 'khdb.txt'
    }

    AfterAll { Stop-FakeStorage $server }

    It 'downloads everything on first run (4 runspaces), normalizing case and HASH:count and merging in order' {
        Publish-Shards @{
            '00.txt' = @('00112233445566778899AABBCCDDEEFF', '00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF')
            'ab.txt' = @('ab112233445566778899aabbccddeeff:12', 'ABFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF')
        }
        Update-ElysiumKhdb -MaxParallelTransfers 4 6>$null
        Get-Content -LiteralPath $khdb | Should -Be @(
            '00112233445566778899AABBCCDDEEFF', '00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
            'AB112233445566778899AABBCCDDEEFF', 'ABFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF')
        (Get-Downloads).Count | Should -Be 3   # manifest + 2 shards
    }

    It 'downloads only the manifest and keeps khdb.txt untouched when nothing changed' {
        $before = (Get-Item -LiteralPath $khdb).LastWriteTimeUtc
        Start-Sleep -Milliseconds 1100   # file times have 1 s resolution on some filesystems
        Update-ElysiumKhdb -MaxParallelTransfers 1 6>$null
        Get-Downloads | Should -Be @('GET bucket/khdb/manifest.json')
        (Get-Item -LiteralPath $khdb).LastWriteTimeUtc | Should -Be $before
    }

    It 'rebuilds khdb.txt when it is missing, even though nothing was downloaded' {
        Remove-Item -LiteralPath $khdb
        Update-ElysiumKhdb -MaxParallelTransfers 1 6>$null
        Get-Downloads | Out-Null   # drain: this test only checks the rebuilt file
        Get-Content -LiteralPath $khdb | Should -Be @(
            '00112233445566778899AABBCCDDEEFF', '00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
            'AB112233445566778899AABBCCDDEEFF', 'ABFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF')
    }

    It 'rebuilds khdb.txt when something replaced it without touching the manifest or shards' {
        # khdb.txt is tracked in git (unlike the shard cache and khdb-build.sha256), so a `git pull`
        # or `checkout` can silently swap a real build for some other file's content.
        Set-Content -LiteralPath $khdb -Value 'not the real khdb content'
        Update-ElysiumKhdb -MaxParallelTransfers 1 6>$null
        Get-Downloads | Out-Null   # drain: shards/manifest are untouched, only khdb.txt is wrong
        Get-Content -LiteralPath $khdb | Should -Be @(
            '00112233445566778899AABBCCDDEEFF', '00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
            'AB112233445566778899AABBCCDDEEFF', 'ABFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF')
    }

    It 'downloads only the changed shard and removes shards the manifest no longer lists' {
        $stale = Join-Path $root 'khdb-shards/zz.txt'
        Set-Content -LiteralPath $stale -Value ('Z' * 32)
        Publish-Shards @{
            '00.txt' = @('00112233445566778899AABBCCDDEEFF', '00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF')
            'ab.txt' = @('ABFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF')
        }
        Update-ElysiumKhdb -MaxParallelTransfers 2 6>$null
        Get-Downloads | Should -Be @('GET bucket/khdb/manifest.json', 'GET bucket/khdb/shards/ab.txt')
        Test-Path -LiteralPath $stale | Should -BeFalse
        Get-Content -LiteralPath $khdb | Should -Be @(
            '00112233445566778899AABBCCDDEEFF', '00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF', 'ABFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF')
    }

    It 'keeps one backup by default, honours KhdbBackupCount, and rejects a bad value' {
        $settingsFile = Join-Path $root 'ElysiumSettings.txt'
        $original = Get-Content -LiteralPath $settingsFile
        $backups = { @(Get-ChildItem -LiteralPath $root -Filter 'khdb.txt.bak-*') }
        $ab = 'ABFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'
        try {
            (& $backups).Count | Should -Be 1   # left by the previous test's rebuild
            $previous = Get-Content -LiteralPath $khdb
            Start-Sleep -Milliseconds 1100      # backup names have 1 s resolution
            Publish-Shards @{ '00.txt' = @('00112233445566778899AABBCCDDEEFF'); 'ab.txt' = @($ab) }
            Update-ElysiumKhdb -MaxParallelTransfers 1 6>$null
            $found = & $backups
            $found.Count | Should -Be 1
            Get-Content -LiteralPath $found[0].FullName | Should -Be $previous

            Add-Content -LiteralPath $settingsFile -Value 'KhdbBackupCount=0'
            Publish-Shards @{ '00.txt' = @('00112233445566778899AABBCCDDEEFE'); 'ab.txt' = @($ab) }
            Update-ElysiumKhdb -MaxParallelTransfers 1 6>$null
            (& $backups).Count | Should -Be 0
            Get-Content -LiteralPath $khdb | Should -Be @('00112233445566778899AABBCCDDEEFE', $ab)

            Set-Content -LiteralPath $settingsFile -Value ($original + 'KhdbBackupCount=many')
            { Update-ElysiumKhdb -MaxParallelTransfers 1 6>$null } | Should -Throw '*KhdbBackupCount*'
        } finally {
            Set-Content -LiteralPath $settingsFile -Value $original
        }
    }

    It 'fails the run and keeps the previous KHDB when a shard does not match its checksum' {
        $before = Get-Content -LiteralPath $khdb
        Publish-Shards @{ '00.txt' = @('00112233445566778899AABBCCDDEEFF'); 'ab.txt' = @('ABFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF') }
        Add-Content -LiteralPath (Join-Path $remote 'bucket/khdb/shards/00.txt') -Value 'tampered'
        { Update-ElysiumKhdb -MaxParallelTransfers 2 6>$null } | Should -Throw '*00.txt*mismatch*'
        Get-Content -LiteralPath $khdb | Should -Be $before
    }

    It 'refuses a manifest whose shard names point outside the shard directory' {
        # What a tampered bucket could serve: a valid checksum for a file meant to land two levels up.
        Publish-Shards @{ '../../escaped.txt' = @('00112233445566778899AABBCCDDEEFF') }
        { Update-ElysiumKhdb -MaxParallelTransfers 1 6>$null } | Should -Throw "*'../../escaped.txt'*"
        Test-Path -LiteralPath (Join-Path $TestDrive 'escaped.txt') | Should -BeFalse
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
    It 'selects a domain by name (case-insensitive) or by prompted number, and rejects bad choices' {
        $domains = Get-DomainDetailsFromSettings -Settings @{
            Domain1Name = 'contoso.local'; Domain1DC = 'dc1.contoso.local'
            Domain2Name = 'fabrikam.local'; Domain2DC = ''
        }
        (Select-ElysiumDomain -DomainDetails $domains -Name 'CONTOSO.local').DC | Should -Be 'dc1.contoso.local'
        { Select-ElysiumDomain -DomainDetails $domains -Name 'other.local' } | Should -Throw "*'other.local' is not configured*contoso.local, fabrikam.local*"
        { Select-ElysiumDomain -DomainDetails $domains -Name 'fabrikam.local' } | Should -Throw '*does not have a configured DC*'
        Mock Read-Host { '1' }
        (Select-ElysiumDomain -DomainDetails $domains 6>$null).Name | Should -Be 'contoso.local'
        Mock Read-Host { '7' }
        { Select-ElysiumDomain -DomainDetails $domains 6>$null } | Should -Throw '*Invalid selection*'
    }

    It 'turns a password-quality result into JSON-ready findings with UPNs, keeping duplicate groups grouped' {
        # Same shapes DSInternals returns: string sets, and a list of sets for DuplicatePasswordGroups.
        $set = { param([string[]]$names) $h = [System.Collections.Generic.HashSet[string]]::new(); foreach ($n in $names) { [void]$h.Add($n) }; ,$h }
        $groups = [System.Collections.Generic.List[object]]::new()
        $groups.Add((& $set 'CONTOSO\bob', 'CONTOSO\carol'))
        $result = [pscustomobject]@{
            WeakPassword            = (& $set 'CONTOSO\alice', 'CONTOSO\svc-sql')
            LMHash                  = (& $set @())
            DuplicatePasswordGroups = $groups
        }
        $upns = @{ alice = 'alice@contoso.com'; bob = 'bob@contoso.com'; carol = 'carol@contoso.com' }
        $json = @(ConvertTo-PasswordQualityFinding -Result $result -UpnBySam $upns) | ConvertTo-Json -Depth 8
        $findings = $json | ConvertFrom-Json

        @($findings.check) | Should -Be @('WeakPassword', 'DuplicatePasswordGroups')   # empty LMHash omitted
        $weak = $findings | Where-Object check -eq 'WeakPassword'
        $weak.count | Should -Be 2
        ($weak.accounts | Where-Object account -eq 'CONTOSO\alice').upn | Should -Be 'alice@contoso.com'
        ($weak.accounts | Where-Object account -eq 'CONTOSO\svc-sql').upn | Should -BeNullOrEmpty
        $dup = $findings | Where-Object check -eq 'DuplicatePasswordGroups'
        $dup.count | Should -Be 1
        @($dup.accounts[0].account | Sort-Object) | Should -Be @('CONTOSO\bob', 'CONTOSO\carol')
        $json | Should -Not -Match '"value"\s*:'   # no PowerShell array-wrapper artefacts
    }

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

    It 'normalizes a file with a blank line or a padded line instead of handing it to DSInternals as is' {
        foreach ($case in @{ name = 'blank'; lines = @(('0' * 32), '', ('A' * 32)) }, @{ name = 'padded'; lines = @(('0' * 32), ('  ' + 'A' * 32)) }) {
            $path = Join-Path $TestDrive "$($case.name).txt"
            Set-Content -LiteralPath $path -Value $case.lines
            $resolved = Resolve-DSInternalsWeakHashFile -Path $path 3>$null 6>$null
            try {
                $resolved.IsTemporary | Should -BeTrue
                Get-Content -LiteralPath $resolved.Path | Should -Be @(('0' * 32), ('A' * 32))
            } finally {
                Remove-Item -LiteralPath $resolved.Path -ErrorAction SilentlyContinue
            }
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

Describe 'KHDB publish -> update round trip' {
    # Runs the real publisher (tools/Prepare-KHDBStorage.ps1), "uploads" its package to the fake store
    # the way the README's CLI commands do, and lets Update-ElysiumKhdb rebuild the KHDB from it.
    BeforeAll {
        Import-Module (Join-Path $PSScriptRoot '../src/Elysium/Elysium.psd1') -Force
        $root = Join-Path $TestDrive 'client'
        $package = Join-Path $TestDrive 'package'
        $remote = Join-Path $TestDrive 'remote'
        New-Item -ItemType Directory -Path $root, (Join-Path $remote 'bucket/khdb') -Force | Out-Null
        & (Get-Module Elysium) { param($r) $script:InstallRoot = $r } $root

        # 400 distinct hashes spread over many two-hex prefixes, pre-sorted as the publisher expects.
        $md5 = [System.Security.Cryptography.MD5]::Create()
        $expected = [string[]](1..400 | ForEach-Object {
            [BitConverter]::ToString($md5.ComputeHash([Text.Encoding]::UTF8.GetBytes("$_"))).Replace('-', '')
        })
        [Array]::Sort($expected, [StringComparer]::Ordinal)
        $source = for ($i = 0; $i -lt $expected.Count; $i++) {
            switch ($i % 4) {
                0 { $expected[$i].ToLowerInvariant() }      # lower case
                1 { "$($expected[$i]):$i" }                # legacy HASH:count
                2 { $expected[$i]; $expected[$i] }          # adjacent duplicate
                default { $expected[$i] }
            }
        }
        $sourcePath = Join-Path $TestDrive 'source.txt'
        Set-Content -LiteralPath $sourcePath -Value (@($source) + 'not-a-hash')
        & (Join-Path $PSScriptRoot '../tools/Prepare-KHDBStorage.ps1') -SourcePath $sourcePath -OutputRoot $package 6>$null 3>$null

        Copy-Item -LiteralPath (Join-Path $package 'shards') -Destination (Join-Path $remote 'bucket/khdb/shards') -Recurse
        Copy-Item -LiteralPath (Join-Path $package 'manifest.json') -Destination (Join-Path $remote 'bucket/khdb/manifest.json')
        $server = Start-FakeStorage -Root $remote
        Set-Content -LiteralPath (Join-Path $root 'ElysiumSettings.txt') -Value ((New-S3Settings $server.Url).GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" })
    }

    AfterAll { Stop-FakeStorage $server }

    It 'publishes valid entries only and the client rebuilds exactly the sorted, unique, upper-case set' {
        (Get-Content -LiteralPath (Join-Path $package 'manifest.json') -Raw | ConvertFrom-Json).shards.Count | Should -BeGreaterThan 100
        Get-Content -LiteralPath (Join-Path $package 'invalid-hashes.txt') | Should -Contain 'not-a-hash'
        Update-ElysiumKhdb -MaxParallelTransfers 8 6>$null
        Get-Content -LiteralPath (Join-Path $root 'khdb.txt') | Should -Be $expected
    }
}

Describe 'Storage transfers' {
    BeforeAll {
        $remote = Join-Path $TestDrive 'store'
        New-Item -ItemType Directory -Path (Join-Path $remote 'bucket/flaky') -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $remote 'bucket/flaky/object.txt') -Value 'eventually'
        $server = Start-FakeStorage -Root $remote
        $s3 = Get-StorageConfig (New-S3Settings $server.Url)
        $body = [System.Text.Encoding]::UTF8.GetBytes('encrypted export bytes')
        $upload = Join-Path $TestDrive 'upload.enc'
        [System.IO.File]::WriteAllBytes($upload, $body)
    }

    AfterAll { Stop-FakeStorage $server }

    BeforeEach { Mock Start-Sleep {} }

    It 'signs an Azure PUT with Content-MD5 and the block-blob headers' {
        $azure = Get-StorageConfig @{ storageAccountName = 'acct'; containerName = 'uploads'; sasToken = 'sv=2022-11-02&sig=x' }
        $request = New-StorageRequest -Storage $azure -Method PUT -Key 'CONTOSO.enc' -Body $body
        $request.RequestUri.AbsoluteUri | Should -Be 'https://acct.blob.core.windows.net/uploads/CONTOSO.enc?sv=2022-11-02&sig=x'
        $request.Headers.GetValues('x-ms-blob-type') | Should -Be 'BlockBlob'
        $md5 = [System.Security.Cryptography.MD5]::Create()
        [Convert]::ToBase64String($request.Content.Headers.ContentMD5) | Should -Be ([Convert]::ToBase64String($md5.ComputeHash($body)))
    }

    It 'rejects incomplete storage settings before anything is sent' {
        { Get-StorageConfig @{ storageAccountName = 'acct'; containerName = 'uploads' } } | Should -Throw '*sasToken*'
        { Get-StorageConfig @{ StorageProvider = 'S3'; s3BucketName = 'b'; s3AccessKeyId = 'a'; s3SecretAccessKey = 's' } } | Should -Throw '*s3EndpointUrl*'
    }

    It 'uploads to S3 in one PUT that the store accepts against the signed SHA-256' {
        Invoke-StorageUpload -Storage $s3 -Key 'uploads/CONTOSO.enc' -Path $upload
        [System.IO.File]::ReadAllBytes((Join-Path $remote 'bucket/uploads/CONTOSO.enc')) | Should -Be $body
        Get-FakeStorageLog $server | Should -Be @('PUT bucket/uploads/CONTOSO.enc')   # no read-back
    }

    It 'surfaces the service error when an upload is rejected' {
        { Invoke-StorageUpload -Storage $s3 -Key 'reject/CONTOSO.enc' -Path $upload } | Should -Throw '*HTTP 400*BadDigest*'
    }

    It 'fails a 404 download at once, without retrying' {
        { Invoke-StorageDownload -Storage $s3 -Key 'missing.txt' -TargetPath (Join-Path $TestDrive 'missing.txt') } | Should -Throw '*HTTP 404*'
        Should -Invoke Start-Sleep -Times 0 -Exactly
    }

    It 'retries a transient 503 and then succeeds' {
        $target = Join-Path $TestDrive 'flaky.txt'
        Invoke-StorageDownload -Storage $s3 -Key 'flaky/object.txt' -TargetPath $target 3>$null
        Get-Content -LiteralPath $target | Should -Be 'eventually'
        Should -Invoke Start-Sleep -Times 1 -Exactly
    }
}

Describe 'Streaming KHDB merge (compiled KhdbMerger)' {
    BeforeAll {
        $shardRoot = Join-Path $TestDrive 'shards'
        New-Item -ItemType Directory -Path $shardRoot -Force | Out-Null
        $manifestFor = { param($names) [pscustomobject]@{ shards = @($names | ForEach-Object { [pscustomobject]@{ name = $_ } }) } }
    }

    It 'normalizes lowercase and HASH:count lines, removes duplicates across shards, and counts them' {
        # Real shards are split by prefix, so each one only holds its own range and the merged order holds.
        Set-Content -LiteralPath (Join-Path $shardRoot '00.txt') -Value @(('0' * 31 + '1'), ('0' * 31 + '1' + ':9'), ('0' * 31 + '2'))
        Set-Content -LiteralPath (Join-Path $shardRoot 'ab.txt') -Value @(('ab' * 16), ('AB' * 16), ('ac' * 16))
        $target = Join-Path $TestDrive 'merged.txt'
        Merge-ShardsToFile -Manifest (& $manifestFor '00.txt', 'ab.txt') -ShardsRoot $shardRoot -TargetPath $target 6>$null
        Get-Content -LiteralPath $target | Should -Be @(('0' * 31 + '1'), ('0' * 31 + '2'), ('AB' * 16), ('AC' * 16))
    }

    It 'names the shard and line of malformed content' {
        Set-Content -LiteralPath (Join-Path $shardRoot 'bad.txt') -Value @(('0' * 32), 'not-a-hash')
        { Merge-ShardsToFile -Manifest (& $manifestFor 'bad.txt') -ShardsRoot $shardRoot -TargetPath (Join-Path $TestDrive 'x.txt') 6>$null } |
            Should -Throw "*'bad.txt' at line 2*"
    }

    It 'rejects a bare count suffix and a non-digit suffix' {
        $bad = Join-Path $TestDrive 'suffix.txt'
        foreach ($line in ('0' * 32 + ':', '0' * 32 + ':x1', '0' * 31)) {
            Set-Content -LiteralPath $bad -Value $line
            { Merge-ShardsToFile -Manifest (& $manifestFor 'suffix.txt') -ShardsRoot $TestDrive -TargetPath (Join-Path $TestDrive 'y.txt') 6>$null } | Should -Throw
        }
    }

    It 'warns about duplicates when validating a finished file' {
        $file = Join-Path $TestDrive 'dups.txt'
        Set-Content -LiteralPath $file -Value @(('0' * 32), ('0' * 32), ('1' * 32))
        $warnings = @(Validate-KHDBFile -Path $file 3>&1 | Where-Object { $_ -is [System.Management.Automation.WarningRecord] } | ForEach-Object { $_.Message })
        ($warnings -join ' ') | Should -Match '1 duplicate'
    }

    It 'merges 300,000 hashes across 256 shards with the same result as a sorted reference' {
        $rng = [System.Random]::new(42)
        $all = [System.Collections.Generic.List[string]]::new()
        $bytes = New-Object byte[] 16
        for ($i = 0; $i -lt 300000; $i++) {
            $rng.NextBytes($bytes)
            $all.Add(([BitConverter]::ToString($bytes).Replace('-', '')))
        }
        $all.Sort([StringComparer]::Ordinal)
        # One pass to bucket the hashes by prefix (the list is already sorted, so each bucket stays sorted).
        $buckets = @{}
        foreach ($hash in $all) {
            $prefix = $hash.Substring(0, 2).ToLowerInvariant()
            if (-not $buckets.ContainsKey($prefix)) { $buckets[$prefix] = [System.Collections.Generic.List[string]]::new() }
            $buckets[$prefix].Add($hash)
        }
        $names = foreach ($prefix in $buckets.Keys | Sort-Object) {
            $name = "$prefix.txt"
            Set-Content -LiteralPath (Join-Path $shardRoot $name) -Value $buckets[$prefix]
            $name
        }
        $target = Join-Path $TestDrive 'big.txt'
        Merge-ShardsToFile -Manifest (& $manifestFor $names) -ShardsRoot $shardRoot -TargetPath $target 6>$null
        (Get-Content -LiteralPath $target).Count | Should -Be 300000
        (Get-Content -LiteralPath $target | Select-Object -First 1) | Should -Be $all[0]
        (Get-Content -LiteralPath $target | Select-Object -Last 1) | Should -Be $all[-1]
    }
}
