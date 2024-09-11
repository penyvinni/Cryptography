import os
import pyDes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Δημιουργία κλειδιού από password και αποθήκευση σε αρχείο μαζί με το αλάτι
def generate_key(password, key_file, key_length=32, iterations=1000):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # Use SHA-256 hash algorithm
        length=key_length,  # Key length in bytes
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    key = kdf.derive(password.encode('utf-8'))
    
    with open(key_file, 'wb') as f:
        f.write(salt + key)
    print(f"Key and salt generated and saved to {key_file}")
    return key

# Φόρτωση κλειδιού και αλατιού από αρχείο
def load_key(key_file, key_length):
    with open(key_file, 'rb') as f:
        data = f.read()
        salt = data[:16]
        key = data[16:16 + key_length]
    return key, salt

# Δημιουργία τυχαίου αρχείου εισόδου
def create_input_file(input_file, size):
    data = os.urandom(size)
    with open(input_file, 'wb') as f:
        f.write(data)
    print(f"Random input file generated and saved to {input_file}")

# Κρυπτογράφηση αρχείου με ή χωρίς Padding
def encrypt_file(input_file, output_file, key, algorithm, iv_length, use_padding=True):
    iv = os.urandom(iv_length)
    if algorithm == pyDes.des:
        cipher = algorithm(key[:8], pyDes.CBC, iv[:8], pad=None, padmode=pyDes.PAD_PKCS5)
    else:
        cipher = Cipher(algorithm(key), modes.CBC(iv), backend=default_backend()).encryptor()

    if use_padding and algorithm != pyDes.des:
        padder = padding.PKCS7(algorithm.block_size).padder()
    
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        f_out.write(iv)
        while True:
            chunk = f_in.read(1024)
            if not chunk:
                break
            if use_padding and algorithm != pyDes.des:
                chunk = padder.update(chunk)
            encrypted_chunk = cipher.update(chunk)
            f_out.write(encrypted_chunk)
        if use_padding and algorithm != pyDes.des:
            f_out.write(cipher.update(padder.finalize()))
        f_out.write(cipher.finalize())
    print(f"File encrypted {'with' if use_padding else 'without'} padding and saved to {output_file}")

# Αποκρυπτογράφηση αρχείου
def decrypt_file(key, input_file, output_file, algorithm, iv_length):
    with open(input_file, 'rb') as f_in:
        iv = f_in.read(iv_length)
    if algorithm == pyDes.des:
        cipher = algorithm(key[:8], pyDes.CBC, iv[:8], pad=None, padmode=pyDes.PAD_PKCS5)
    else:
        cipher = Cipher(algorithm(key), modes.CBC(iv), backend=default_backend()).decryptor()
    
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        f_in.read(iv_length)  # Αγνοούμε το IV που είναι στην αρχή του αρχείου
        while True:
            chunk = f_in.read(1024)
            if not chunk:
                break
            decrypted_chunk = cipher.update(chunk)
            f_out.write(decrypted_chunk)
        f_out.write(cipher.finalize())
    print(f"File decrypted successfully. Decrypted output saved to {output_file}")

def main():
    key_file = 'keyfile.key'
    input_file = 'input.txt'
    encrypted_file = 'encrypted.enc'
    decrypted_file = 'decrypted.txt'

    # Επιλογή αλγορίθμου
    algorithm_choice = input("Choose encryption algorithm 'AES' or 'DES': ").strip().upper()
    if algorithm_choice not in ["AES", "DES"]:
        print("Invalid algorithm!")
        return
    
    # Ορισμός αλγορίθμου κρυπτογράφησης
    if algorithm_choice == "AES":
        algorithm = algorithms.AES
        key_length = 32     # Μήκος κλειδιού : 256 bits
        iv_length = 16      # Μήκος IV για AES: 16 bytes
    elif algorithm_choice == "DES":
        algorithm = pyDes.des
        key_length = 8      # Μήκος κλειδιού : 64 bits (8 bytes)
        iv_length = 8       # Μήκος IV για DES: 8 bytes

    print(f"The Encryption Algorithm that you choose is: {algorithm_choice}.")
    
    # Ρώτημα για τον κωδικό
    password = input("Enter a password for key generation: ").strip()
    
    # Δημιουργία κλειδιού από password και αποθήκευση σε αρχείο
    key = generate_key(password, key_file, key_length)
    
    # Δημιουργία τυχαίου αρχείου εισόδου
    create_input_file(input_file, 100)  # Δημιουργία αρχείου εισόδου 100 bytes

    # Κρυπτογράφηση αρχείου με ή χωρίς Padding
    choice = input("Do you want to encrypt with padding? (yes/no): ").strip().lower()
    use_padding = True if choice == 'yes' else False
    
    encrypt_file(input_file, encrypted_file, key, algorithm, iv_length, use_padding)

    # Αποκρυπτογράφηση του κρυπτογραφημένου αρχείου
    decrypt_file(key, encrypted_file, decrypted_file, algorithm, iv_length)

if __name__ == "__main__":
    main()