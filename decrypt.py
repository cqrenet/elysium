##################################################
##   ____ ___  ____  _____   _   _ _____ _____  ##
##  / ___/ _ \|  _ \| ____| | \ | | ____|_   _| ##
## | |  | | | | |_) |  _|   |  \| |  _|   | |   ##
## | |__| |_| |  _ <| |___ _| |\  | |___  | |   ##
##  \____\__\_\_| \_\_____(_)_| \_|_____| |_|   ##
##################################################
## Project: Elysium                             ##
## File: decrypt.py                             ##
## Version: 1.0.0                               ##
## Support: support@cqre.net                    ##
##################################################

# Installation notes:
# Install PyCryptodome with "pip install pycryptodome". Must be run with python3.

from Crypto.Cipher import AES
import hashlib
import os

# Ask for the encrypted file's name
encrypted_file_name = input("Enter the name of the encrypted file (with .enc extension): ")
encrypted_file_path = f'path/to/your/encrypted/{encrypted_file_name}'
decrypted_file_path = encrypted_file_path.replace('.enc', '.zip')

# Try to retrieve the passphrase from the environment variable
passphrase = os.getenv('ELYSIUM_PASSPHRASE')

if passphrase is None:
    passphrase = input("Passphrase not found in environment. Please enter the passphrase: ")
    # Here, you might save the passphrase to a temporary session or file, but be cautious with security.

# Derive the AES key from the passphrase
key = hashlib.sha256(passphrase.encode()).digest()

try:
    # Read the encrypted file
    with open(encrypted_file_path, 'rb') as encrypted_file:
        iv = encrypted_file.read(16)  # The first 16 bytes are the IV
        encrypted_data = encrypted_file.read()

    # Decrypt the data
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(encrypted_data)

    # Remove potential PKCS#7 padding
    pad_len = decrypted_data[-1]
    decrypted_data = decrypted_data[:-pad_len]

    # Write the decrypted data to a file
    with open(decrypted_file_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted_data)

    print(f"File has been decrypted: {decrypted_file_path}")
except Exception as e:
    print(f"An error occurred: {str(e)}")
