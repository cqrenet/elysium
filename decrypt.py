##################################################
##   ____ ___  ____  _____   _   _ _____ _____  ##
##  / ___/ _ \|  _ \| ____| | \ | | ____|_   _| ##
## | |  | | | | |_) |  _|   |  \| |  _|   | |   ##
## | |__| |_| |  _ <| |___ _| |\  | |___  | |   ##
##  \____\__\_\_| \_\_____(_)_| \_|_____| |_|   ##
##################################################
## Project: Elysium                             ##
## File: decrypt.py                             ##
## Version: 1.1.0                               ##
## Support: support@cqre.net                    ##
##################################################

# Installation notes:
# Install PyCryptodome with "pip install pycryptodome". Must be run with python3.

import getpass
import hashlib
import hmac
import os
import sys

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

PBKDF2_ITERATIONS = 100000


def derive_keys(passphrase: str, salt: bytes, length: int) -> bytes:
    # Must match .NET Rfc2898DeriveBytes(string, salt, 100000, SHA256) in Extract-NTHashes.ps1:
    # UTF-8 password bytes and an HMAC-SHA256 PRF. Successive GetBytes() calls there continue one
    # output stream, so its GetBytes(32) + GetBytes(32) equals the first 64 bytes here.
    return hashlib.pbkdf2_hmac('sha256', passphrase.encode('utf-8'), salt, PBKDF2_ITERATIONS, length)


def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext), AES.block_size)


def decrypt_ely2(data: bytes, passphrase: str) -> bytes:
    # 'ELY2' | salt(16) | iv(16) | ciphertext | HMAC-SHA256(32) over everything before it
    if len(data) < 4 + 16 + 16 + 16 + 32:
        raise ValueError("Encrypted data too short for ELY2 format")
    body, mac = data[:-32], data[-32:]
    keys = derive_keys(passphrase, data[4:20], 64)
    # Verify before decrypting: CBC alone can't tell a wrong passphrase from tampered data.
    if not hmac.compare_digest(mac, hmac.new(keys[32:], body, hashlib.sha256).digest()):
        raise ValueError("HMAC check failed: wrong passphrase, or the file is corrupted or was modified")
    return aes_cbc_decrypt(keys[:32], data[20:36], body[36:])


def decrypt_ely1(data: bytes, passphrase: str) -> bytes:
    # 'ELY1' | salt(16) | iv(16) | ciphertext - no MAC, so a wrong passphrase shows up only as a padding error
    if len(data) < 4 + 16 + 16:
        raise ValueError("Encrypted data too short for ELY1 format")
    return aes_cbc_decrypt(derive_keys(passphrase, data[4:20], 32), data[20:36], data[36:])


def decrypt_legacy(data: bytes, passphrase: str) -> bytes:
    # Pre-ELY1: key = SHA-256(passphrase), iv(16) | ciphertext
    if len(data) < 16:
        raise ValueError("Encrypted data too short for legacy format")
    return aes_cbc_decrypt(hashlib.sha256(passphrase.encode()).digest(), data[:16], data[16:])


def decrypt(data: bytes, passphrase: str) -> bytes:
    if data.startswith(b"ELY2"):
        return decrypt_ely2(data, passphrase)
    if data.startswith(b"ELY1"):
        return decrypt_ely1(data, passphrase)
    return decrypt_legacy(data, passphrase)


def main():
    encrypted_file_path = os.path.abspath(input("Enter the name of the encrypted file (with .enc extension): "))
    if not encrypted_file_path.endswith('.enc'):
        sys.exit("Expected a file with the .enc extension.")
    decrypted_file_path = encrypted_file_path[:-len('.enc')] + '.zip'

    passphrase = os.getenv('ELYSIUM_PASSPHRASE')
    if passphrase is None:
        passphrase = getpass.getpass("Passphrase not found in environment. Please enter the passphrase: ")

    try:
        with open(encrypted_file_path, 'rb') as encrypted_file:
            decrypted_data = decrypt(encrypted_file.read(), passphrase)
        with open(decrypted_file_path, 'wb') as decrypted_file:
            decrypted_file.write(decrypted_data)
    except Exception as e:
        sys.exit(f"An error occurred: {e}")

    print(f"File has been decrypted: {decrypted_file_path}")


if __name__ == '__main__':
    main()
