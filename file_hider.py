import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
import os
import struct
import argparse
import sys
import io

# Dummy stream to handle write calls when sys.stderr is None
class DummyStream(io.StringIO):
    def write(self, txt):
        pass

# Check if stderr is None and replace it with the dummy stream
if sys.stderr is None:
    sys.stderr = DummyStream()

# Constants
SALT_SIZE = 16
NUM_ITERATIONS = 100000
KEY_SIZE = 32  # 256 bits for AES-256
IV_SIZE = 16
NUM_LAYERS = 7
FILENAME_SIZE = 255  # Maximum filename length

# Function to encrypt data with AES and then encrypt AES key with RSA
def encrypt_data(data, public_key_path):
    with open(public_key_path, 'rb') as f:
        public_key = RSA.import_key(f.read())
    cipher_rsa = PKCS1_OAEP.new(public_key)
    
    session_key = get_random_bytes(16)  # AES key length (128 bits)
    salt = get_random_bytes(SALT_SIZE)
    key = PBKDF2(session_key, salt, dkLen=KEY_SIZE, count=NUM_ITERATIONS)
    
    for _ in range(NUM_LAYERS):
        iv = get_random_bytes(IV_SIZE)
        cipher_aes = AES.new(key, AES.MODE_CBC, iv)
        data = cipher_aes.encrypt(pad(data, AES.block_size))
        data = iv + data  # Prepend IV to the ciphertext for each layer
    
    enc_session_key = cipher_rsa.encrypt(session_key)
    return enc_session_key, salt, data

# Function to decrypt AES key with RSA and then decrypt data with AES
def decrypt_data(enc_session_key, salt, data, private_key_path, passphrase):
    with open(private_key_path, 'rb') as f:
        private_key = RSA.import_key(f.read(), passphrase=passphrase)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    
    session_key = cipher_rsa.decrypt(enc_session_key)
    key = PBKDF2(session_key, salt, dkLen=KEY_SIZE, count=NUM_ITERATIONS)
    
    for _ in range(NUM_LAYERS):
        iv = data[:IV_SIZE]
        data = data[IV_SIZE:]
        cipher_aes = AES.new(key, AES.MODE_CBC, iv)
        data = unpad(cipher_aes.decrypt(data), AES.block_size)
    
    return data




if __name__ == '__main__':

    root = tk.Tk()
    root.withdraw()  # Hide the root window

    # Check if any arguments were provided
    if len(sys.argv) > 1:


        # Add command line argument parsing
        parser = argparse.ArgumentParser(description="File Hider")
        parser.add_argument('--hide', action='store_true', help='Hide and encrypt a file')
        parser.add_argument('--unhide', action='store_true', help='Decrypt and unhide a file')
        parser.add_argument('--host', type=str, help='Path to the host file')
        parser.add_argument('--file', type=str, help='Path to the file to hide')
        parser.add_argument('--public-key', type=str, help='Path to the public key file')
        parser.add_argument('--private-key', type=str, help='Path to the private key file')
        parser.add_argument('--output', type=str, help='Path to save the modified host file or extracted file')
        parser.add_argument('--passphrase', type=str, help='Passphrase for the private key', default='')
        try:
            args = parser.parse_args()
        except SystemExit:
            # When bad arguments are provided, show the help message in a messagebox
            error_message = parser.format_help()
            messagebox.showerror("Argument Error", error_message)
            sys.exit(1)

        if args.hide and args.host and args.file and args.public_key and args.output:
            try:
                with open(args.host, 'rb') as host_file:
                    host_data = host_file.read()
                
                with open(args.file, 'rb') as hidden_file:
                    hidden_data = hidden_file.read()
                
                enc_session_key, salt, encrypted_hidden_data = encrypt_data(hidden_data, args.public_key)
                
                full_filename = os.path.basename(args.file).encode('utf-8')
                full_filename += b' ' * (FILENAME_SIZE - len(full_filename))
                
                with open(args.output, 'wb') as output_file:
                    output_file.write(host_data)
                    output_file.write(enc_session_key)
                    output_file.write(salt)
                    output_file.write(full_filename)
                    output_file.write(encrypted_hidden_data)
                    output_file.write(struct.pack('<IIII', len(enc_session_key), len(salt), FILENAME_SIZE, len(encrypted_hidden_data)))
                
                print("The file has been successfully hidden and encrypted within the host file!")
            except Exception as e:
                print("Error:", str(e))
                messagebox.showerror("Argument Error", "Missing arguments for hiding a file.")
            sys.exit()

        elif args.unhide and args.host and args.private_key and args.output:
            try:
                with open(args.host, 'rb') as host_file:
                    host_file.seek(-16, os.SEEK_END)
                    enc_session_key_size, salt_size, filename_size, encrypted_hidden_data_size = struct.unpack('<IIII', host_file.read(16))
                    host_file.seek(0)
                    host_data = host_file.read()
                    enc_session_key = host_data[-(16 + enc_session_key_size + salt_size + filename_size + encrypted_hidden_data_size):-16 - salt_size - filename_size - encrypted_hidden_data_size]
                    salt = host_data[-(16 + salt_size + filename_size + encrypted_hidden_data_size):-16 - filename_size - encrypted_hidden_data_size]
                    full_filename = host_data[-(16 + filename_size + encrypted_hidden_data_size):-16 - encrypted_hidden_data_size].rstrip(b' ')
                    encrypted_hidden_data = host_data[-(16 + encrypted_hidden_data_size):-16]
                
                decrypted_data = decrypt_data(enc_session_key, salt, encrypted_hidden_data, args.private_key, args.passphrase)
                
                with open(args.output, 'wb') as output_file:
                    output_file.write(decrypted_data)
                
                print(f"Hidden file was successfully decrypted and extracted to {args.output}!")
            except Exception as e:
                print("Error:", str(e))
                messagebox.showerror("Argument Error", "Missing arguments for unhiding a file.")

            sys.exit()

        else:
            messagebox.showerror("Argument Error", "Missing arguments")

        sys.exit()

    else:



        root = tk.Tk()
        root.title("File Hider")

        # Center the window on the screen
        window_width = 400
        window_height = 150
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        center_x = int(screen_width / 2 - window_width / 2)
        center_y = int(screen_height / 2 - window_height / 2)
        root.geometry(f'{window_width}x{window_height}+{center_x}+{center_y}')

        # Function to hide and encrypt a file within another file
        def hide_file():
            host_file_path = filedialog.askopenfilename(title="Select the host file", filetypes=[("All Files", "*.*")])
            if not host_file_path:
                return
            
            hidden_file_path = filedialog.askopenfilename(title="Select the file to hide", filetypes=[("All Files", "*.*")])
            if not hidden_file_path:
                return
            
            public_key_path = filedialog.askopenfilename(title="Select the public key file", filetypes=[("PEM Files", "*.pem")])
            if not public_key_path:
                return
            
            output_path = filedialog.asksaveasfilename(title="Save the modified host file", defaultextension=os.path.splitext(host_file_path)[1])
            if not output_path:
                return
            
            try:
                with open(host_file_path, 'rb') as host_file:
                    host_data = host_file.read()
                
                with open(hidden_file_path, 'rb') as hidden_file:
                    hidden_data = hidden_file.read()
                
                enc_session_key, salt, encrypted_hidden_data = encrypt_data(hidden_data, public_key_path)
                
                # Save the file extension and filename of the hidden file
                full_filename = os.path.basename(hidden_file_path).encode('utf-8')
                full_filename += b' ' * (FILENAME_SIZE - len(full_filename))  # Pad the full filename to FILENAME_SIZE
                
                with open(output_path, 'wb') as output_file:
                    output_file.write(host_data)
                    output_file.write(enc_session_key)
                    output_file.write(salt)
                    output_file.write(full_filename)  # Write the padded full filename
                    output_file.write(encrypted_hidden_data)
                    # Store the sizes of the encrypted session key, salt, full filename, and encrypted hidden data
                    output_file.write(struct.pack('<IIII', len(enc_session_key), len(salt), FILENAME_SIZE, len(encrypted_hidden_data)))
                
                messagebox.showinfo("Success", "The file has been successfully hidden and encrypted within the host file!")
            except Exception as e:
                messagebox.showerror("Error", str(e))

        # Function to extract and decrypt the hidden file from the host file
        def unhide_file():
            host_file_path = filedialog.askopenfilename(title="Select the modified host file", filetypes=[("All Files", "*.*")])
            if not host_file_path:
                return
            
            private_key_path = filedialog.askopenfilename(title="Select the private key file", filetypes=[("PEM Files", "*.pem")])
            if not private_key_path:
                return
            
            passphrase = simpledialog.askstring("Passphrase", "Enter the passphrase for the private key:", show="*")
            if passphrase is None:  # Allow empty passphrase (not recommended)
                passphrase = ''
            
            try:
                with open(host_file_path, 'rb') as host_file:
                    host_file.seek(-16, os.SEEK_END)  # Seek to the last 16 bytes where the sizes are stored
                    enc_session_key_size, salt_size, filename_size, encrypted_hidden_data_size = struct.unpack('<IIII', host_file.read(16))
                    host_file.seek(0)
                    host_data = host_file.read()
                    # Extract the encrypted session key, salt, full filename, and encrypted hidden data
                    enc_session_key = host_data[-(16 + enc_session_key_size + salt_size + filename_size + encrypted_hidden_data_size):-16 - salt_size - filename_size - encrypted_hidden_data_size]
                    salt = host_data[-(16 + salt_size + filename_size + encrypted_hidden_data_size):-16 - filename_size - encrypted_hidden_data_size]
                    full_filename = host_data[-(16 + filename_size + encrypted_hidden_data_size):-16 - encrypted_hidden_data_size].rstrip(b' ')  # Remove padding
                    encrypted_hidden_data = host_data[-(16 + encrypted_hidden_data_size):-16]
                
                decrypted_data = decrypt_data(enc_session_key, salt, encrypted_hidden_data, private_key_path, passphrase)
                
                # Ask for the directory to save the file
                output_directory = filedialog.askdirectory(title="Select the output directory")
                if not output_directory:
                    return
                
                # Ask for the new filename, providing the original as the default
                original_filename = full_filename.decode('utf-8')
                new_filename = simpledialog.askstring("New Filename", "Enter a new filename or use the original:", initialvalue=original_filename)
                if new_filename is None:
                    return
                
                # Automatically generate the output path with the new filename and extension
                output_path = os.path.join(output_directory, new_filename)
                
                with open(output_path, 'wb') as output_file:
                    output_file.write(decrypted_data)
                
                messagebox.showinfo("Success", f"Hidden file was successfully decrypted and extracted to {output_path}!")
            except Exception as e:
                messagebox.showerror("Error", str(e))

        # GUI buttons
        hide_button = tk.Button(root, text="Hide and Encrypt File", command=hide_file)
        hide_button.pack(fill=tk.X, expand=True, padx=10, pady=5)

        unhide_button = tk.Button(root, text="Decrypt and Unhide File", command=unhide_file)
        unhide_button.pack(fill=tk.X, expand=True, padx=10, pady=5)

        root.mainloop()
