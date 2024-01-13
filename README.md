# File Hider

File Hider is a sophisticated tool that allows you to securely hide and encrypt a file within another file using multiple layers of AES-256 encryption, with the AES key itself being encrypted using RSA.

## Features

- Multi-layered encryption: Each file is encrypted with AES-256 not once, but seven times for added security.
- RSA encryption: The AES key is encrypted with RSA, ensuring that only the holder of the private key can decrypt the hidden file.
- Secure hiding: The encrypted file is hidden within another file, making it difficult to detect that a hidden file exists.
- File name preservation: The original file is preserved and can be restored upon decryption.
- Rename option: Provides the ability to rename the original file before saving it during the unhide process.

## How to Use

### Key Generation

Generate an RSA key pair for encryption and decryption:

1. Open a terminal or command prompt.
2. Generate a private key with AES-256 encryption:

   `openssl genpkey -algorithm RSA -out pri_filehider.pem -aes256 -pkeyopt rsa_keygen_bits:4096 -pass pass:your_password`

   Replace `your_password` with a strong passphrase.

3. Extract the public key from the private key:

   `openssl rsa -pubout -in pri_filehider.pem -out pub_filehider.pem -passin pass:your_password`

   Use the same passphrase as before.

### Hide a File

1. Run the File Hider application.
2. Click "Hide and Encrypt File".
3. Select a host file to contain the hidden file.
4. Select the file to hide and encrypt.
5. Select the public key file (`pub_filehider.pem`) for RSA encryption.
6. Choose a location and name for the modified host file.
7. The application encrypts and hides the file within the host file.

### Unhide a File

1. Run the File Hider application.
2. Click "Decrypt and Unhide File".
3. Select the modified host file with the hidden file.
4. Select the private key file (`pri_filehider.pem`) for RSA decryption.
5. Enter the passphrase for the private key.
6. Choose the output directory for the decrypted file.
7. Optionally, rename the original file before saving.
8. The application decrypts and extracts the hidden file.

## Windows Executable

For Windows users, a standalone executable is provided which does not require any dependencies to be installed. Simply download the `.exe` file and run it on your Windows system. [Download the latest release](https://github.com/x011/File_Hider/releases)

## Dependencies (for Python script)

- Python 3
- Tkinter (usually with Python)
- PyCryptodome (`pip install pycryptodome`)
- OpenSSL (for key generation)

## Security Features

- **Multi-layer Encryption**: The application encrypts the file using AES-256 encryption seven times with different keys and IVs, significantly increasing the complexity and security.
- **RSA Key Encryption**: The AES session key is encrypted with a RSA public key, ensuring that only the private key holder can decrypt it.
- **Secure Key Derivation**: Uses PBKDF2 with HMAC-SHA256 for secure key derivation.
- **Random IVs and Salts**: Each layer of encryption uses a random IV, and the key derivation uses a random salt, enhancing security against certain types of attacks.

## Security Note

While this tool uses strong encryption algorithms, security also depends on the RSA key strength, private key secrecy, and passphrase strength. Keep your private key secure and use a strong passphrase.

## Disclaimer

For educational purposes only. The author is not responsible for misuse or damage.

## License

MIT License - see LICENSE file for details.
