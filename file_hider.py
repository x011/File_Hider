import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
import os
import struct

# Constants
SALT_SIZE = 16
NUM_ITERATIONS = 100000
KEY_SIZE = 32  # 256 bits for AES-256
IV_SIZE = 16
NUM_LAYERS = 7
EXT_SIZE = 10  # Maximum file extension length
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
        file_extension = os.path.splitext(hidden_file_path)[1].encode('utf-8')
        file_extension += b' ' * (EXT_SIZE - len(file_extension))  # Pad the file extension to EXT_SIZE
        filename = os.path.basename(hidden_file_path).encode('utf-8')
        filename += b' ' * (FILENAME_SIZE - len(filename))  # Pad the filename to FILENAME_SIZE
        
        with open(output_path, 'wb') as output_file:
            output_file.write(host_data)
            output_file.write(enc_session_key)
            output_file.write(salt)
            output_file.write(file_extension)  # Write the padded file extension
            output_file.write(filename)  # Write the padded filename
            output_file.write(encrypted_hidden_data)
            # Store the sizes of the encrypted session key, salt, file extension, filename, and encrypted hidden data
            output_file.write(struct.pack('<IIIII', len(enc_session_key), len(salt), EXT_SIZE, FILENAME_SIZE, len(encrypted_hidden_data)))
        
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
            host_file.seek(-20, os.SEEK_END)  # Seek to the last 20 bytes where the sizes are stored
            enc_session_key_size, salt_size, ext_size, filename_size, encrypted_hidden_data_size = struct.unpack('<IIIII', host_file.read(20))
            host_file.seek(0)
            host_data = host_file.read()
            # Extract the encrypted session key, salt, file extension, filename, and encrypted hidden data
            enc_session_key = host_data[-(20 + enc_session_key_size + salt_size + ext_size + filename_size + encrypted_hidden_data_size):-20 - salt_size - ext_size - filename_size - encrypted_hidden_data_size]
            salt = host_data[-(20 + salt_size + ext_size + filename_size + encrypted_hidden_data_size):-20 - ext_size - filename_size - encrypted_hidden_data_size]
            file_extension = host_data[-(20 + ext_size + filename_size + encrypted_hidden_data_size):-20 - filename_size - encrypted_hidden_data_size].rstrip(b' ')  # Remove padding
            filename = host_data[-(20 + filename_size + encrypted_hidden_data_size):-20 - encrypted_hidden_data_size].rstrip(b' ')  # Remove padding
            encrypted_hidden_data = host_data[-(20 + encrypted_hidden_data_size):-20]
        
        decrypted_data = decrypt_data(enc_session_key, salt, encrypted_hidden_data, private_key_path, passphrase)
        
        # Ask for the directory to save the file
        output_directory = filedialog.askdirectory(title="Select the output directory")
        if not output_directory:
            return
        
        # Ask for the new filename, providing the original as the default
        original_filename = filename.decode('utf-8')
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
