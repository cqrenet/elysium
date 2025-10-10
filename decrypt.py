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

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import hashlib
import os

# Ask for the encrypted file's name
encrypted_file_name = input("Enter the name of the encrypted file (with .enc extension): ")
encrypted_file_path = encrypted_file_name if os.path.isabs(encrypted_file_name) else os.path.join(os.getcwd(), encrypted_file_name)
decrypted_file_path = encrypted_file_path.replace('.enc', '.zip')

# Try to retrieve the passphrase from the environment variable
passphrase = os.getenv('ELYSIUM_PASSPHRASE')

if passphrase is None:
    passphrase = input("Passphrase not found in environment. Please enter the passphrase: ")
    # Here, you might save the passphrase to a temporary session or file, but be cautious with security.

def decrypt_legacy(data: bytes, key_bytes: bytes) -> bytes:
    if len(data) < 16:
        raise ValueError("Encrypted data too short for legacy format")
    iv = data[:16]
    encrypted = data[16:]
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(encrypted)
    pad_len = plaintext[-1]
    if not (1 <= pad_len <= 16):
        raise ValueError("Invalid padding length in legacy data")
    return plaintext[:-pad_len]

def decrypt_pbkdf2(data: bytes, passphrase: str) -> bytes:
    if len(data) < 4 + 16 + 16:
        raise ValueError("Encrypted data too short for PBKDF2 format")
    magic = data[:4]
    if magic != b"ELY1":
        raise ValueError("Invalid magic header for PBKDF2 format")
    salt = data[4:20]
    iv = data[20:36]
    encrypted = data[36:]
    key = PBKDF2(passphrase, salt, dkLen=32, count=100000)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(encrypted)
    pad_len = plaintext[-1]
    if not (1 <= pad_len <= 16):
        raise ValueError("Invalid padding length in PBKDF2 data")
    return plaintext[:-pad_len]

try:
    # Read the encrypted file
    with open(encrypted_file_path, 'rb') as encrypted_file:
        blob = encrypted_file.read()

    # Try PBKDF2 format first (ELY1 header), then legacy fallback
    if blob.startswith(b"ELY1"):
        decrypted_data = decrypt_pbkdf2(blob, passphrase)
    else:
        # Legacy key derivation: SHA-256(passphrase), IV is first 16 bytes
        legacy_key = hashlib.sha256(passphrase.encode()).digest()
        decrypted_data = decrypt_legacy(blob, legacy_key)

    # Write the decrypted data to a file
    with open(decrypted_file_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted_data)

    print(f"File has been decrypted: {decrypted_file_path}")
except Exception as e:
    print(f"An error occurred: {str(e)}")
