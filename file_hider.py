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
import base64
import zlib

class DummyStream(io.StringIO):
    def write(self, txt):
        pass

if sys.stderr is None:
    sys.stderr = DummyStream()

SALT_SIZE = 16
NUM_ITERATIONS = 100000
KEY_SIZE = 32
IV_SIZE = 16
NUM_LAYERS = 7
FILENAME_SIZE = 255

def encrypt_data(data, public_key_path):
    with open(public_key_path, 'rb') as f:
        public_key = RSA.import_key(f.read())
    cipher_rsa = PKCS1_OAEP.new(public_key)
    
    session_key = get_random_bytes(16)
    salt = get_random_bytes(SALT_SIZE)
    key = PBKDF2(session_key, salt, dkLen=KEY_SIZE, count=NUM_ITERATIONS)
    
    data = zlib.compress(data)

    for _ in range(NUM_LAYERS):
        iv = get_random_bytes(IV_SIZE)
        cipher_aes = AES.new(key, AES.MODE_CBC, iv)
        data = cipher_aes.encrypt(pad(data, AES.block_size))
        data = iv + data
    
    enc_session_key = cipher_rsa.encrypt(session_key)
    enc_session_key_b64 = base64.b64encode(enc_session_key).decode('utf-8')
    salt_b64 = base64.b64encode(salt).decode('utf-8')
    data_b64 = base64.b64encode(data).decode('utf-8')
    return enc_session_key_b64, salt_b64, data_b64

def decrypt_data(enc_session_key_b64, salt_b64, data_b64, private_key_path, passphrase):
    with open(private_key_path, 'rb') as f:
        private_key = RSA.import_key(f.read(), passphrase=passphrase)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    
    session_key = cipher_rsa.decrypt(base64.b64decode(enc_session_key_b64))
    salt = base64.b64decode(salt_b64)
    data = base64.b64decode(data_b64)
    
    key = PBKDF2(session_key, salt, dkLen=KEY_SIZE, count=NUM_ITERATIONS)
    
    for _ in range(NUM_LAYERS):
        iv = data[:IV_SIZE]
        data = data[IV_SIZE:]
        cipher_aes = AES.new(key, AES.MODE_CBC, iv)
        data = unpad(cipher_aes.decrypt(data), AES.block_size)
    
    # Decompress the data after decrypting
    data = zlib.decompress(data)
    
    return data

if __name__ == '__main__':
    root = tk.Tk()
    root.withdraw()

    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser(description="File Hider")
        parser.add_argument('--hide', action='store_true', help='Hide and encrypt a file')
        parser.add_argument('--unhide', action='store_true', help='Decrypt and unhide a file')
        parser.add_argument('--host', type=str, help='Path to the host file')
        parser.add_argument('--file', type=str, help='Path to the file to hide')
        parser.add_argument('--public-key', type=str, help='Path to the public key file')
        parser.add_argument('--private-key', type=str, help='Path to the private key file')
        parser.add_argument('--output', type=str, help='Path to save the modified host file or extracted file')
        parser.add_argument('--passphrase', type=str, help='Passphrase for the private key', default='')
        args = parser.parse_args()

        if args.hide and args.host and args.file and args.public_key and args.output:
            try:
                with open(args.host, 'rb') as host_file:
                    host_data = host_file.read()
                
                with open(args.file, 'rb') as hidden_file:
                    hidden_data = hidden_file.read()
                
                enc_session_key_b64, salt_b64, encrypted_hidden_data_b64 = encrypt_data(hidden_data, args.public_key)
                
                full_filename = os.path.basename(args.file).encode('utf-8')
                full_filename_b64 = base64.b64encode(full_filename).decode('utf-8')
                full_filename_b64 += ' ' * (FILENAME_SIZE - len(full_filename_b64))
                
                with open(args.output, 'wb') as output_file:
                    output_file.write(host_data)
                    output_file.write(enc_session_key_b64.encode('utf-8'))
                    output_file.write(salt_b64.encode('utf-8'))
                    output_file.write(full_filename_b64.encode('utf-8'))
                    output_file.write(encrypted_hidden_data_b64.encode('utf-8'))
                    output_file.write(struct.pack('<IIII', len(enc_session_key_b64), len(salt_b64), FILENAME_SIZE, len(encrypted_hidden_data_b64)))
                
                print("The file has been successfully hidden and encrypted within the host file!")
            except Exception as e:
                print("Error:", str(e))
                messagebox.showerror("Error", "An error occurred while hiding the file.")
            sys.exit()

        elif args.unhide and args.host and args.private_key and args.output:
            try:
                with open(args.host, 'rb') as host_file:
                    host_file.seek(-16, os.SEEK_END)
                    enc_session_key_size, salt_size, filename_size, encrypted_hidden_data_size = struct.unpack('<IIII', host_file.read(16))
                    host_file.seek(0)
                    host_data = host_file.read()
                    enc_session_key_b64 = host_data[-(16 + enc_session_key_size + salt_size + filename_size + encrypted_hidden_data_size):-16 - salt_size - filename_size - encrypted_hidden_data_size].decode('utf-8')
                    salt_b64 = host_data[-(16 + salt_size + filename_size + encrypted_hidden_data_size):-16 - filename_size - encrypted_hidden_data_size].decode('utf-8')
                    full_filename_b64 = host_data[-(16 + filename_size + encrypted_hidden_data_size):-16 - encrypted_hidden_data_size].decode('utf-8').rstrip(' ')
                    encrypted_hidden_data_b64 = host_data[-(16 + encrypted_hidden_data_size):-16].decode('utf-8')
                
                decrypted_data = decrypt_data(enc_session_key_b64, salt_b64, encrypted_hidden_data_b64, args.private_key, args.passphrase)
                
                with open(args.output, 'wb') as output_file:
                    output_file.write(decrypted_data)
                
                print(f"Hidden file was successfully decrypted and extracted to {args.output}!")
            except Exception as e:
                print("Error:", str(e))
                messagebox.showerror("Error", "An error occurred while unhiding the file.")
            sys.exit()

        else:
            messagebox.showerror("Error", "Missing arguments")
            sys.exit()

    else:
        root = tk.Tk()
        root.title("File Hider")

        # Center the window on the screen
        window_width = 300
        window_height = 100
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        center_x = int(screen_width / 2 - window_width / 2)
        center_y = int(screen_height / 2 - window_height / 2)
        root.geometry(f'{window_width}x{window_height}+{center_x}+{center_y}')

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
                
                enc_session_key_b64, salt_b64, encrypted_hidden_data_b64 = encrypt_data(hidden_data, public_key_path)
                
                full_filename = os.path.basename(hidden_file_path).encode('utf-8')
                full_filename_b64 = base64.b64encode(full_filename).decode('utf-8')
                full_filename_b64 += ' ' * (FILENAME_SIZE - len(full_filename_b64))
                
                with open(output_path, 'wb') as output_file:
                    output_file.write(host_data)
                    output_file.write(enc_session_key_b64.encode('utf-8'))
                    output_file.write(salt_b64.encode('utf-8'))
                    output_file.write(full_filename_b64.encode('utf-8'))
                    output_file.write(encrypted_hidden_data_b64.encode('utf-8'))
                    output_file.write(struct.pack('<IIII', len(enc_session_key_b64), len(salt_b64), FILENAME_SIZE, len(encrypted_hidden_data_b64)))
                
                messagebox.showinfo("Success", "The file has been successfully hidden and encrypted within the host file!")
            except Exception as e:
                messagebox.showerror("Error", "An error occurred while hiding the file: " + str(e))

        def unhide_file():
            host_file_path = filedialog.askopenfilename(title="Select the modified host file", filetypes=[("All Files", "*.*")])
            if not host_file_path:
                return
            
            private_key_path = filedialog.askopenfilename(title="Select the private key file", filetypes=[("PEM Files", "*.pem")])
            if not private_key_path:
                return
            
            passphrase = simpledialog.askstring("Passphrase", "Enter the passphrase for the private key:", show="*")
            if passphrase is None:
                passphrase = ''
            
            try:
                with open(host_file_path, 'rb') as host_file:
                    host_file.seek(-16, os.SEEK_END)
                    enc_session_key_size, salt_size, filename_size, encrypted_hidden_data_size = struct.unpack('<IIII', host_file.read(16))
                    host_file.seek(0)
                    host_data = host_file.read()
                    enc_session_key_b64 = host_data[-(16 + enc_session_key_size + salt_size + filename_size + encrypted_hidden_data_size):-16 - salt_size - filename_size - encrypted_hidden_data_size].decode('utf-8')
                    salt_b64 = host_data[-(16 + salt_size + filename_size + encrypted_hidden_data_size):-16 - filename_size - encrypted_hidden_data_size].decode('utf-8')
                    full_filename_b64 = host_data[-(16 + filename_size + encrypted_hidden_data_size):-16 - encrypted_hidden_data_size].decode('utf-8').rstrip(' ')
                    encrypted_hidden_data_b64 = host_data[-(16 + encrypted_hidden_data_size):-16].decode('utf-8')
                
                decrypted_data = decrypt_data(enc_session_key_b64, salt_b64, encrypted_hidden_data_b64, private_key_path, passphrase)
                
                original_filename = base64.b64decode(full_filename_b64).decode('utf-8')
                
                output_directory = filedialog.askdirectory(title="Select the output directory")
                if not output_directory:
                    return
                
                new_filename = simpledialog.askstring("New Filename", "Enter a new filename or use the original:", initialvalue=original_filename)
                if new_filename is None:
                    return
                
                output_path = os.path.join(output_directory, new_filename)
                
                with open(output_path, 'wb') as output_file:
                    output_file.write(decrypted_data)
                
                messagebox.showinfo("Success", f"Hidden file was successfully decrypted and extracted to {output_path}!")
            except Exception as e:
                messagebox.showerror("Error", "An error occurred while unhiding the file: " + str(e))


        hide_button = tk.Button(root, text="Hide and Encrypt File", command=hide_file)
        hide_button.pack(fill=tk.X, expand=True, padx=10, pady=5)

        unhide_button = tk.Button(root, text="Decrypt and Unhide File", command=unhide_file)
        unhide_button.pack(fill=tk.X, expand=True, padx=10, pady=5)

        root.mainloop()
