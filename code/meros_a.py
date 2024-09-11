import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Function to generate a key based on a password and save it along with the salt to a file
def generate_and_save_key(password, key_file, key_length=16, iterations=1000):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # Use the SHA-1 hash algorithm
        length=key_length,  # Length of the key in bytes (16 bytes = 128 bits)
        salt=salt,  # The salt
        iterations=iterations,  # Number of iterations
        backend=default_backend()
    )

    key = kdf.derive(password.encode('utf-8'))
    
    with open(key_file, 'wb') as f:
        f.write(salt + key)
    print(f"Key and salt generated and saved to {key_file}")
    
    return key, salt

# Function to load the key and salt from a file
def load_key_and_salt(key_file, key_length):
    with open(key_file, 'rb') as f:
        data = f.read()
        salt = data[:16]
        key = data[16:16 + key_length]
    return key, salt

# Function to create a random input file of specified size
def create_input_file(input_file, size):
    data = os.urandom(size)
    with open(input_file, 'wb') as f:
        f.write(data)
    print(f"Input file generated and saved to {input_file}")

# Function to encrypt a file with padding
# 4. Κρυπτογράφηση με Padding: Αν ο χρήστης επιλέξει padding, το αρχείο κρυπτογραφείται και το padding εφαρμόζεται 
# για να εξασφαλιστεί ότι τα δεδομένα είναι πολλαπλάσια του μεγέθους του block.
def encrypt_file(input_file, output_file, key, algorithm, iv_length):
    iv = os.urandom(iv_length)
    cipher = Cipher(algorithm(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithm.block_size).padder()

    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        f_out.write(iv)
        while True:
            chunk = f_in.read(1024)
            if len(chunk) == 0:
                break
            chunk = padder.update(chunk)
            f_out.write(encryptor.update(chunk))
        f_out.write(encryptor.update(padder.finalize()))
        f_out.write(encryptor.finalize())
    print(f"File encrypted with padding and saved to {output_file}")

# Function to encrypt a file without padding
# 5. Κρυπτογράφηση χωρίς Padding: Αν ο χρήστης επιλέξει χωρίς padding, ελέγχεται αν το μέγεθος του αρχείου είναι πολλαπλάσιο των 16 bytes πριν την κρυπτογράφηση.
def encrypt_file_no_padding(input_file, output_file, key, algorithm, iv_length):
    iv = os.urandom(iv_length)
    cipher = Cipher(algorithm(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        f_out.write(iv)
        while True:
            chunk = f_in.read(algorithm.block_size // 8)
            if len(chunk) == 0:
                break
            f_out.write(encryptor.update(chunk))
        f_out.write(encryptor.finalize())
    print(f"File encrypted without padding and saved to {output_file}")

# Main function to create and encrypt files
def main():
    key_file = 'keyfile.key'
    input_file = 'input_a.txt'
    output_file_with_padding = 'output_with_padding.enc'
    output_file_no_padding = 'output_no_padding.enc'

    # Prompt user to choose encryption algorithm
    algorithm_choice = input("Choose encryption algorithm 'AES' or '3DES': ").strip().upper()
    
    # Define encryption algorithm and parameters
    if algorithm_choice == "AES":
        algorithm = algorithms.AES
        key_length = 32  # Key length: 256 bits
        iv_length = 16   # IV length for AES: 16 bytes
    elif algorithm_choice == "3DES":
        algorithm = algorithms.TripleDES
        key_length = 24  # Key length: 192 bits
        iv_length = 8    # IV length for 3DES: 8 bytes
    else:
        print("Invalid algorithm!")
        return

    # Prompt user for password
    password = input("Enter a password for key generation: ").strip()
    
    # Generate key based on password and save to file
    key, salt = generate_and_save_key(password, key_file, key_length=key_length)
    
    # Prompt user to choose padding option
    choice = input("Do you want to encrypt with Padding? (yes/no): ").strip().lower()
    
    if choice == 'yes':
        # Create input file
        create_input_file(input_file, 100)  # Create input file with 100 bytes
        file_size = os.path.getsize(input_file)
        print(f"Input file size: {file_size} bytes.")  # Print input file size
        # Encrypt with padding
        encrypt_file(input_file, output_file_with_padding, key, algorithm, iv_length)
    elif choice == 'no':
        # Create input file with size multiple of the block size
        block_size = 16 if algorithm_choice == "AES" else 8
        create_input_file(input_file, block_size * 6)  # Create input file with size multiple of block size
        file_size = os.path.getsize(input_file)
        print(f"Input file size: {file_size} bytes.")  # Print input file size
        if file_size % block_size != 0:
            print("Error: The file size is not a multiple of the block size.")
        else:
            # Encrypt without padding
            try:
                encrypt_file_no_padding(input_file, output_file_no_padding, key, algorithm, iv_length)
            except ValueError as e:
                print(e)
    else:
        print("Invalid choice. Please enter 'yes' or 'no'.")

if __name__ == "__main__":
    main()
    
# generate_key: Δημιουργεί ένα τυχαίο κλειδί AES 256-bit και το αποθηκεύει σε αρχείο.
# create_input_file: Δημιουργεί ένα αρχείο εισόδου με τυχαία δεδομένα.
# load_key: Φορτώνει το κλειδί από το αρχείο.
# encrypt_file: Κρυπτογραφεί το αρχείο εισόδου με padding PKCS7 και αποθηκεύει το κρυπτογραφημένο αρχείο.
# encrypt_file_no_padding: Κρυπτογραφεί το αρχείο εισόδου χωρίς padding και αποθηκεύει το κρυπτογραφημένο αρχείο.
# main: Δημιουργεί το κλειδί και το αρχείο εισόδου, και εκτελεί την κρυπτογράφηση και με τις δύο μεθόδους.
# Προστέθηκε η δυνατότητα στον χρήστη να επιλέγει αν θέλει να κρυπτογραφήσει με padding ή χωρίς padding.
# Η επιλογή γίνεται μέσω του input και ελέγχεται η απάντηση για να εκτελεστεί η κατάλληλη κρυπτογράφηση.
# Αν ο χρήστης επιλέξει "yes", εκτελείται η κρυπτογράφηση με padding.
# Αν ο χρήστης επιλέξει "no", εκτελείται η κρυπτογράφηση χωρίς padding.
# Αν η επιλογή δεν είναι "yes" ή "no", εμφανίζεται μήνυμα σφάλματος.


# Εξήγηση:
# 1. Δημιουργία Κλειδιού: Το κλειδί δημιουργείται και αποθηκεύεται στο keyfile.key.
# 2. Δημιουργία Αρχείου Εισόδου: Ένα αρχείο εισόδου δημιουργείται με τυχαία δεδομένα και συγκεκριμένο μέγεθος.
# 3. Επιλογή Padding: Ο χρήστης επιλέγει αν θέλει να κρυπτογραφήσει το αρχείο με padding ή όχι.
# 4. Κρυπτογράφηση με Padding: Αν ο χρήστης επιλέξει padding, το αρχείο κρυπτογραφείται και το padding εφαρμόζεται για να εξασφαλιστεί ότι τα δεδομένα είναι πολλαπλάσια του μεγέθους του block.
# 5. Κρυπτογράφηση χωρίς Padding: Αν ο χρήστης επιλέξει χωρίς padding, ελέγχεται αν το μέγεθος του αρχείου είναι πολλαπλάσιο των 16 bytes πριν την κρυπτογράφηση.
#    Κατά την κρυπτογράφηση, διαβάζονται chunks των 16 bytes και κρυπτογραφούνται χωρίς να εφαρμόζεται padding.
# Αυτός ο κώδικας θα εξασφαλίσει ότι η κρυπτογράφηση εκτελείται σωστά τόσο με padding όσο και χωρίς padding, και ότι οι έλεγχοι για το μέγεθος του αρχείου γίνονται σωστά.