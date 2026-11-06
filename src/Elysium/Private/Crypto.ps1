# AES export format ELY2 (see README / decrypt.py): PBKDF2-SHA256 -> AES-256-CBC + HMAC-SHA256.

function Protect-FileWithAES {
    param (
        [Parameter(Mandatory = $true)]
        [string]$InputFile,

        [Parameter(Mandatory = $true)]
        [string]$OutputFile,

        [Parameter(Mandatory = $true)]
        [string]$Passphrase
    )

    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $salt = New-Object byte[] 16
    $rng.GetBytes($salt)

    # Derive two independent keys from one PBKDF2 byte stream: the first 32 bytes for AES-256, the
    # next 32 for HMAC-SHA256 (Rfc2898DeriveBytes.GetBytes returns a continuous stream across
    # calls on the same instance, so these two ranges never overlap). CBC alone gives no integrity
    # check - tampered or corrupted ciphertext just decrypts to garbage (or throws an unhelpful
    # padding exception) instead of being detected. Encrypt-then-MAC over magic+salt+iv+ciphertext
    # (format 'ELY2') catches both. Older 'ELY1' files this script produced have no MAC.
    $kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Passphrase, $salt, 100000, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $aesKey = $kdf.GetBytes(32)
    $hmacKey = $kdf.GetBytes(32)

    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize = 256
    $aes.BlockSize = 128
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.GenerateIV()
    $iv = $aes.IV

    $encryptor = $aes.CreateEncryptor($aesKey, $iv)
    $hmac = [System.Security.Cryptography.HMACSHA256]::new($hmacKey)
    try {
        $plainBytes = [System.IO.File]::ReadAllBytes($InputFile)
        $cipherBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)

        $magic = [System.Text.Encoding]::ASCII.GetBytes('ELY2')
        $header = $magic + $salt + $iv
        $mac = $hmac.ComputeHash($header + $cipherBytes)

        [System.IO.File]::WriteAllBytes($OutputFile, ($header + $cipherBytes + $mac))
    } finally {
        $encryptor.Dispose(); $hmac.Dispose(); $aes.Dispose(); $rng.Dispose(); $kdf.Dispose()
    }

    Write-Host "File has been encrypted (PBKDF2+AES-256-CBC+HMAC-SHA256): $OutputFile"
}
