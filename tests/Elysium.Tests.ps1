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
