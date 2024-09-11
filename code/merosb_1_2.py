import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from pyDes import des, CBC, PAD_PKCS5  # pip install pyDes

# Function to generate a key based on a password and save it along with the salt to a file
def generate_and_save_key(password, key_file, key_length=32, iterations=1000):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # Use the SHA-1 hash algorithm
        length=key_length,  # Length of the key in bytes (32 bytes = 256 bits for AES)
        salt=salt,  # The salt
        iterations=iterations,  # Number of iterations
        backend=default_backend()
    )

    key = kdf.derive(password.encode('utf-8'))
    
    with open(key_file, 'wb') as f:
        f.write(salt + key)
    print(f"Key and salt generated and saved to {key_file}")
    
    return key, salt

def generate_and_save_des_key(password, key_file, iterations=1000):
    key_length = 8  # Length of the key in bytes (8 bytes = 64 bits for DES)
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA1(),
        length=key_length,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )

    key = kdf.derive(password.encode('utf-8'))
    
    with open(key_file, 'wb') as f:
        f.write(salt + key)
    print(f"DES key and salt generated and saved to {key_file}")
    
    return key, salt

# Function to load the key and salt from a file
def load_key_and_salt(key_file, key_length):
    with open(key_file, 'rb') as f:
        data = f.read()
        salt = data[:16]
        key = data[16:16 + key_length]
    return key, salt

# Function to create a random encrypted input file
def create_input_file(input_file, size, key, algorithm, iv_length):
    iv = os.urandom(iv_length)  # Create a random IV
    data = os.urandom(size)  # Create random data
    cipher = Cipher(algorithm(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()  # Encrypt data

    with open(input_file, 'wb') as f:
        f.write(iv + encrypted_data)
    print(f"Encrypted input file generated and saved to {input_file}")

# Function to create a random encrypted input file with DES
def create_input_file_des(input_file, size, key, iv_length):
    iv = os.urandom(iv_length)  # Create a random IV
    data = os.urandom(size)  # Create random data
    des_cipher = des(key, CBC, iv, pad=None, padmode=PAD_PKCS5)
    encrypted_data = des_cipher.encrypt(data)  # Encrypt data

    with open(input_file, 'wb') as f:
        f.write(iv + encrypted_data)
    print(f"Encrypted input file generated and saved to {input_file}")

# Function to decrypt the file
def decrypt_file(key, input_file, output_file, algorithm, iv_length):
    with open(input_file, 'rb') as f_in:
        iv = f_in.read(iv_length)  # Read the IV from the file

    cipher = Cipher(algorithm(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        f_in.read(iv_length)  # Skip the first block which is the IV
        while True:
            chunk = f_in.read(16)  # Read blocks of 16 bytes
            if not chunk:
                break
            decrypted_chunk = decryptor.update(chunk)
            f_out.write(decrypted_chunk)
        f_out.write(decryptor.finalize())

# Function to decrypt the file with DES
def decrypt_file_des(key, input_file, output_file, iv_length):
    with open(input_file, 'rb') as f_in:
        iv = f_in.read(iv_length)  # Read the IV from the file

    des_cipher = des(key, CBC, iv, pad=None, padmode=PAD_PKCS5)

    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        f_in.read(iv_length)  # Skip the first block which is the IV
        encrypted_data = f_in.read()  # Read the encrypted data
        decrypted_data = des_cipher.decrypt(encrypted_data)
        f_out.write(decrypted_data)

def main():
    key_file = 'keyfile.key'
    input_file = 'input_b1.enc'
    output_file = 'output_b1.txt'

    # Choose encryption algorithm
    algorithm_choice = input("Choose encryption algorithm 'AES' or 'DES': ").strip().upper()
    
    # Define encryption algorithm and parameters
    if algorithm_choice == "AES":
        algorithm = algorithms.AES
        key_length = 32  # Key length: 256 bits
        iv_length = 16   # IV length for AES: 16 bytes
    elif algorithm_choice == "DES":
        algorithm = "DES"
        key_length = 8  # Key length: 64 bits
        iv_length = 8   # IV length for DES: 8 bytes
    else:
        print("Invalid algorithm!")
        return
    
    print(f"The Encryption Algorithm that you chose is: {algorithm_choice}.")

    # Prompt user for password
    password = input("Enter a password for key generation: ").strip()
    
    # Generate key based on password and save to file
    if algorithm_choice == "AES":
        key, salt = generate_and_save_key(password, key_file, key_length=key_length)
        # Load the key and salt from the file
        key, salt = load_key_and_salt(key_file, key_length)
        # Create encrypted input file
        create_input_file(input_file, 96, key, algorithm, iv_length)  # Create random encrypted input file
        # Decrypt the input file
        decrypt_file(key, input_file, output_file, algorithm, iv_length)  # Decrypt the input file
    else:
        key, salt = generate_and_save_des_key(password, key_file)
        # Load the key and salt from the file
        key, salt = load_key_and_salt(key_file, key_length)
        # Create encrypted input file with DES
        create_input_file_des(input_file, 96, key, iv_length)  # Create random encrypted input file
        # Decrypt the input file with DES
        decrypt_file_des(key, input_file, output_file, iv_length)  # Decrypt the input file

    print(f"File decrypted successfully. Decrypted output saved to {output_file}.")

if __name__ == "__main__":
    main()