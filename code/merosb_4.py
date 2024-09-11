import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from PIL import Image
import matplotlib.pyplot as plt

# Function to generate a key from a password and save it to a file along with the salt
def generate_key(password, key_file, key_length=32, iterations=100000):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    key = kdf.derive(password.encode('utf-8'))
    with open(key_file, 'wb') as f:
        f.write(salt + key)
    print(f"Key and salt generated and saved to {key_file}")
    return key

# Function to load the key and salt from a file
def load_key(key_file, password, key_length=32, iterations=100000):
    with open(key_file, 'rb') as f:
        data = f.read()
        salt = data[:16]
        key = data[16:]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    kdf.verify(password.encode('utf-8'), key)
    return key

# Function to create a random input file
def create_input_file(input_file, size):
    data = os.urandom(size)
    with open(input_file, 'wb') as f:
        f.write(data)
    print(f"Random input file generated and saved to {input_file}")

# Function to encrypt file using ECB mode
def encrypt_file_ecb(input_file, output_file, key, algorithm):
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        header = f_in.read(54)  # Read the BMP header
        f_out.write(header)     # Write the BMP header to the encrypted file

        plaintext = f_in.read()
        padder = padding.PKCS7(algorithm.block_size).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()
        cipher = Cipher(algorithm(key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        f_out.write(ciphertext)
    print(f"File encrypted using ECB mode and saved to {output_file}")


# Function to encrypt file using CBC mode
def encrypt_file_cbc(input_file, output_file, key, algorithm, iv_length):
    iv = os.urandom(iv_length)
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        header = f_in.read(54)  # Read the BMP header
        f_out.write(header)     # Write the BMP header to the encrypted file
        f_out.write(iv)         # Write IV to the beginning of the encrypted data

        plaintext = f_in.read()
        padder = padding.PKCS7(algorithm.block_size).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()
        cipher = Cipher(algorithm(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        f_out.write(ciphertext)
    print(f"File encrypted using CBC mode and saved to {output_file}")
    


# Function to encrypt file using OFB mode
def encrypt_file_ofb(input_file, output_file, key, algorithm, iv_length):
    iv = os.urandom(iv_length)
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        header = f_in.read(54)  # Read the BMP header
        f_out.write(header)     # Write the BMP header to the encrypted file
        f_out.write(iv)         # Write IV to the beginning of the encrypted data

        plaintext = f_in.read()
        padder = padding.PKCS7(algorithm.block_size).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()
        cipher = Cipher(algorithm(key), modes.OFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        f_out.write(ciphertext)
    print(f"File encrypted using OFB mode and saved to {output_file}")
    


# Function to encrypt file using CFB mode
def encrypt_file_cfb(input_file, output_file, key, algorithm, iv_length):
    iv = os.urandom(iv_length)
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        header = f_in.read(54)  # Read the BMP header
        f_out.write(header)     # Write the BMP header to the encrypted file
        f_out.write(iv)         # Write IV to the beginning of the encrypted data

        plaintext = f_in.read()
        padder = padding.PKCS7(algorithm.block_size).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()
        cipher = Cipher(algorithm(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        f_out.write(ciphertext)
    print(f"File encrypted using CFB mode and saved to {output_file}")
    


# Function to encrypt file using CTR mode
def encrypt_file_ctr(input_file, output_file, key, algorithm, iv_length):
    iv = os.urandom(iv_length)
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        header = f_in.read(54)  # Read the BMP header
        f_out.write(header)     # Write the BMP header to the encrypted file
        f_out.write(iv)         # Write IV to the beginning of the encrypted data

        plaintext = f_in.read()
        padder = padding.PKCS7(algorithm.block_size).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()
        cipher = Cipher(algorithm(key), modes.CTR(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        f_out.write(ciphertext)
    print(f"File encrypted using CTR mode and saved to {output_file}")



# Function to restore BMP header
def restore_bmp_header(original_file, encrypted_file, restored_file):
    with open(original_file, 'rb') as f_orig, open(encrypted_file, 'rb') as f_enc, open(restored_file, 'wb') as f_rest:
        header = f_orig.read(54)  # Read the BMP header from the original file
        f_rest.write(header)      # Write the BMP header to the restored file
        f_rest.write(f_enc.read()[54:])  # Write the rest of the encrypted content
    print(f"BMP header restored in {restored_file}")



# Function to visualize images
def visualize_images(original_bmp, encrypted_bmp_ecb, restored_bmp_ecb, encrypted_bmp_cbc, restored_bmp_cbc, encrypted_bmp_ofb, restored_bmp_ofb, encrypted_bmp_cfb, restored_bmp_cfb):
    # Open the images
    original_image = Image.open(original_bmp)
    encrypted_image_ecb = Image.open(encrypted_bmp_ecb)
    restored_image_ecb = Image.open(restored_bmp_ecb)
    encrypted_image_cbc = Image.open(encrypted_bmp_cbc)
    restored_image_cbc = Image.open(restored_bmp_cbc)


    encrypted_image_ofb = Image.open(encrypted_bmp_ofb)
    restored_image_ofb = Image.open(restored_bmp_ofb)
    encrypted_image_cfb = Image.open(encrypted_bmp_cfb)
    restored_image_cfb = Image.open(restored_bmp_cfb)
    
    # Display the images
    plt.figure(figsize=(15, 5))
    
    plt.subplot(2, 3, 1)
    plt.title('Original Image')
    plt.imshow(original_image)
    
    plt.subplot(2, 3, 2)
    plt.title('Encrypted Image (ECB)')
    plt.imshow(encrypted_image_ecb)
    
    plt.subplot(2, 3, 3)
    plt.title('Restored Image (ECB)')
    plt.imshow(restored_image_ecb)
    
    plt.subplot(2, 3, 5)
    plt.title('Encrypted Image (CBC)')
    plt.imshow(encrypted_image_cbc)
    
    plt.subplot(2, 3, 6)
    plt.title('Restored Image (CBC)')
    plt.imshow(restored_image_cbc)
    
    plt.show()



    plt.figure(figsize=(15, 5))
    
    plt.subplot(2, 3, 1)
    plt.title('Original Image')
    plt.imshow(original_image)
    
    plt.subplot(2, 3, 2)
    plt.title('Encrypted Image (OFB)')
    plt.imshow(encrypted_image_ofb)
    
    plt.subplot(2, 3, 3)
    plt.title('Restored Image (OFB)')
    plt.imshow(restored_image_ofb)
    
    plt.subplot(2, 3, 5)
    plt.title('Encrypted Image (CFB)')
    plt.imshow(encrypted_image_cfb)
    
    plt.subplot(2, 3, 6)
    plt.title('Restored Image (CFB)')
    plt.imshow(restored_image_cfb)
    
    plt.show()



def main():
    key_file = 'keyfile.key'
    input_file = 'security_2.bmp'

    encrypted_file_ecb = 'security-ecb.bmp'
    restored_file_ecb = 'restored-ecb.bmp'

    encrypted_file_cbc = 'security-cbc.bmp'
    restored_file_cbc = 'restored-cbc.bmp'
    
    encrypted_file_ofb = 'security-ofb.bmp'
    restored_file_ofb = 'restored-ofb.bmp'

    encrypted_file_cfb = 'security-cfb.bmp'
    restored_file_cfb = 'restored-cfb.bmp'

    encrypted_file_ctr = 'security-ctr.bmp'
    restored_file_ctr = 'restored-ctr.bmp'


    # Get password from user
    password = input("Enter a password for key generation: ").strip()

    # Generate a key from the password and save it to a file
    key = generate_key(password, key_file)

    # Encrypt the BMP file using ECB mode
    encrypt_file_ecb(input_file, encrypted_file_ecb, key, algorithms.AES)

    # Encrypt the BMP file using CBC mode
    encrypt_file_cbc(input_file, encrypted_file_cbc, key, algorithms.AES, 16)

    # Encrypt the BMP file using OFB mode
    encrypt_file_ofb(input_file, encrypted_file_ofb, key, algorithms.AES, 16)

    # Encrypt the BMP file using CFB mode
    encrypt_file_cfb(input_file, encrypted_file_cfb, key, algorithms.AES, 16)

    # Encrypt the BMP file using CTR mode
    encrypt_file_ctr(input_file, encrypted_file_ctr, key, algorithms.AES, 16)

    # Restore BMP header for encrypted files
    restore_bmp_header(input_file, encrypted_file_ecb, restored_file_ecb)
    restore_bmp_header(input_file, encrypted_file_cbc, restored_file_cbc)
    restore_bmp_header(input_file, encrypted_file_ofb, restored_file_ofb)
    restore_bmp_header(input_file, encrypted_file_cfb, restored_file_cfb)
    
    # Visualize the original, encrypted, and restored images
    visualize_images(input_file, encrypted_file_ecb, restored_file_ecb, encrypted_file_cbc, restored_file_cbc, encrypted_file_ofb, restored_file_ofb, encrypted_file_cfb, restored_file_cfb)

if __name__ == "__main__":
    main()

    
# Steps:
# Generate the key and encrypt the image: This is done using the provided script.
# Restore the BMP header: As per the script, the header from the original BMP file is copied to the encrypted file.
# Visualize the original and encrypted images: Using Python's Pillow library to open and display the images.

# Explanation:
# Key Generation: Generates a random key for AES encryption.
# ECB Encryption: Encrypts the entire BMP file using AES in ECB mode and pads the plaintext to make its length a multiple of the block size.
# Header Restoration: Copies the first 54 bytes (header) from the original BMP file to the encrypted BMP file to ensure it can be opened as an image.
# Visualization: Uses Pillow to open and matplotlib to display the original and encrypted images side-by-side.

# Expected Results:
# Original Image: Should display as the original, unaltered BMP image.
# Encrypted Image: Should display the image with a noticeable pattern disruption caused by the ECB encryption mode, highlighting the fact that ECB mode does not hide data patterns effectively.

# Explanation:
# Key Generation: The generate_key function generates a random key for AES encryption.
# ECB Encryption: The encrypt_file_ecb function reads the BMP file, pads the data, encrypts it using ECB mode, and writes the encrypted data to a new file.
# CBC Encryption: The encrypt_file_cbc function reads the BMP file, generates a random IV, writes the IV to the new file, pads the data, encrypts it using CBC mode, and writes the encrypted data to the file.
# Header Restoration: The restore_bmp_header function copies the first 54 bytes (header) from the original BMP file to the encrypted BMP files to ensure they can be opened as images.
# Visualization: The visualize_images function uses Pillow to open and matplotlib to display the original, ECB-encrypted, and CBC-encrypted images side-by-side for comparison.

# Αρχική εικόνα:
# Η αρχική εικόνα δείχνει μια καθαρή εικόνα προσγείωσης αεροπλάνου με φόντο το ηλιοβασίλεμα.

# Κρυπτογραφημένη εικόνα (ECB):
# Η κρυπτογραφημένη εικόνα ECB εμφανίζεται ως μια θορυβώδης, τυχαιοποιημένη έκδοση της αρχικής εικόνας.
# Είναι ορατή κάποια μπλοκώδης δομή, η οποία είναι ένα χαρακτηριστικό τεχνούργημα της λειτουργίας ECB, όπου πανομοιότυπα μπλοκ απλού κειμένου παράγουν πανομοιότυπα μπλοκ κρυπτοκειμένου.

# Αποκατασταθείσα εικόνα (ECB):
# Η αποκατεστημένη εικόνα ECB παρουσιάζει ένα παρόμοιο θορυβώδες μοτίβο με την κρυπτογραφημένη εικόνα ECB.
# Η αποκατάσταση της επικεφαλίδας BMP λειτούργησε, αλλά η εγγενής αδυναμία της λειτουργίας ECB σημαίνει ότι ορισμένα μοτίβα από την αρχική εικόνα μπορεί να είναι ακόμη διακριτά, αν και πολύ υποβαθμισμένα.

# Κρυπτογραφημένη εικόνα (CBC):
# Η κρυπτογραφημένη εικόνα CBC εμφανίζεται επίσης ως μια θορυβώδης, τυχαιοποιημένη έκδοση της αρχικής εικόνας.
# Σε αντίθεση με τη λειτουργία ECB, δεν υπάρχουν ορατές δομές μπλοκ, επειδή η λειτουργία CBC εισάγει τυχαιότητα μέσω της αλυσιδωτής σύνδεσης και των διανυσμάτων αρχικοποίησης (IV), παρέχοντας ισχυρότερη κρυπτογράφηση.

# Αποκατεστημένη εικόνα (CBC):
# Η αποκατεστημένη εικόνα CBC μοιάζει σχεδόν πανομοιότυπη με την κρυπτογραφημένη εικόνα CBC, επιβεβαιώνοντας την αποτελεσματικότητα της λειτουργίας CBC στη διάχυση των μοτίβων ακόμη και κατά την αποκατάσταση της επικεφαλίδας.

# Σύγκριση:

# ECB Mode:
# Τόσο η κρυπτογραφημένη όσο και η αποκατεστημένη εικόνα ECB εμφανίζουν κάποια υπολείμματα της αρχικής δομής της εικόνας λόγω της προβλέψιμης φύσης της κρυπτογράφησης ECB. Αυτό καθιστά την ΕΚΤ λιγότερο ασφαλή για δεδομένα εικόνας, καθώς τα μοτίβα του απλού κειμένου μπορούν να διακριθούν στο κρυπτογράφημα.

# Λειτουργία CBC:
# Τόσο οι κρυπτογραφημένες όσο και οι αποκαταστημένες εικόνες CBC εμφανίζονται ως πλήρης θόρυβος χωρίς διακριτά μοτίβα από την αρχική εικόνα. Η χρήση ενός IV και η αλυσιδωτή χρήση της λειτουργίας CBC την καθιστά πολύ πιο ασφαλή για την κρυπτογράφηση δεδομένων εικόνας, αποκρύπτοντας αποτελεσματικά τα μοτίβα και παρέχοντας μια ομοιόμορφα τυχαία εμφάνιση.

# Συμπέρασμα:

# Ο τρόπος ECB δεν είναι κατάλληλος για την κρυπτογράφηση εικόνων λόγω της ευπάθειάς του στη διαρροή μοτίβων, η οποία μπορεί να φανεί στην αποκατεστημένη εικόνα ECB.
# Το CBC Mode παρέχει πολύ καλύτερη ασφάλεια για την κρυπτογράφηση εικόνων, όπως αποδεικνύεται από την πλήρη τυχαιότητα τόσο στην κρυπτογραφημένη όσο και στην αποκατεστημένη εικόνα CBC.
# Η οπτική σύγκριση αναδεικνύει τις διαφορές στην ασφάλεια και τη διάχυση μοτίβων μεταξύ των τρόπων ECB και CBC, αποδεικνύοντας τη σημασία της επιλογής του σωστού τρόπου κρυπτογράφησης για ευαίσθητα δεδομένα όπως οι εικόνες.