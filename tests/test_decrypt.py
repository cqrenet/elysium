# ELY2 round trip: encrypt with the real Protect-FileWithAES (src/Elysium/Private/Crypto.ps1, via
# pwsh), decrypt with decrypt.py. Catches any drift between the two sides of the format.
# Run: python3 tests/test_decrypt.py   (needs pwsh on PATH and pycryptodome)

import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'tools'))
import decrypt  # noqa: E402

ENCRYPT_PS1 = r'''
param($Crypto, $In, $Out, $Pass)
$ErrorActionPreference = 'Stop'
. $Crypto
Protect-FileWithAES -InputFile $In -OutputFile $Out -Passphrase $Pass 6>$null
'''


def encrypt_with_powershell(plaintext: bytes, passphrase: str) -> bytes:
    with tempfile.TemporaryDirectory() as d:
        src, dst, ps1 = (os.path.join(d, n) for n in ('in.zip', 'out.enc', 'encrypt.ps1'))
        with open(src, 'wb') as f:
            f.write(plaintext)
        with open(ps1, 'w', encoding='utf-8') as f:
            f.write(ENCRYPT_PS1)
        subprocess.run(['pwsh', '-NoProfile', '-File', ps1,
                        '-Crypto', os.path.join(ROOT, 'src', 'Elysium', 'Private', 'Crypto.ps1'),
                        '-In', src, '-Out', dst, '-Pass', passphrase], check=True)
        with open(dst, 'rb') as f:
            return f.read()


def assert_rejected(blob: bytes, passphrase: str):
    try:
        decrypt.decrypt(blob, passphrase)
    except ValueError as e:
        assert 'HMAC' in str(e), e
    else:
        raise AssertionError('tampered/wrong-passphrase input was accepted')


plaintext = os.urandom(1000)
for passphrase in ('correct horse battery staple', 'pässwörd-€'):  # ASCII + non-ASCII
    blob = encrypt_with_powershell(plaintext, passphrase)
    assert blob[:4] == b'ELY2', blob[:4]
    assert decrypt.decrypt(blob, passphrase) == plaintext, passphrase

assert_rejected(blob, 'wrong passphrase')
assert_rejected(blob[:40] + bytes([blob[40] ^ 1]) + blob[41:], passphrase)  # flipped ciphertext bit
print('ok')
