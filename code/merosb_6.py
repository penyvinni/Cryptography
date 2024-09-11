import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Generate a key from a password and save it to a file along with the salt
def generate_key(password, key_file, key_length=24, iterations=100000):
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

# Load the key from a file using the password
def load_key(key_file, password, key_length=24, iterations=100000):
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
    derived_key = kdf.derive(password.encode('utf-8'))
    return derived_key

# Encrypt data using Triple DES with three keys
# Δημιουργεί ένα IV (Initialization Vector) για την κρυπτογράφηση.
# Δημιουργεί τρία αντικείμενα Cipher για τα τρία κλειδιά, χρησιμοποιώντας το CBC mode και το ίδιο IV.
# Δημιουργεί τα αντίστοιχα encryptors και decryptors.
# Προσθέτει padding στα δεδομένα σύμφωνα με το PKCS7.
# Κρυπτογραφεί τα δεδομένα με το πρώτο κλειδί, αποκρυπτογραφεί με το δεύτερο, και κρυπτογραφεί ξανά με το τρίτο κλειδί.
def triple_des_encrypt_3keys(plain_text, key1, key2, key3):
    iv = os.urandom(8)  # IV for TripleDES is 8 bytes
    cipher1 = Cipher(algorithms.TripleDES(key1), modes.CBC(iv), backend=default_backend())
    cipher2 = Cipher(algorithms.TripleDES(key2), modes.CBC(iv), backend=default_backend())
    cipher3 = Cipher(algorithms.TripleDES(key3), modes.CBC(iv), backend=default_backend())

    encryptor1 = cipher1.encryptor()
    decryptor2 = cipher2.decryptor()
    encryptor3 = cipher3.encryptor()

    padder = padding.PKCS7(algorithms.TripleDES.block_size).padder()
    padded_text = padder.update(plain_text) + padder.finalize()

    encrypted_text1 = encryptor1.update(padded_text) + encryptor1.finalize()
    decrypted_text2 = decryptor2.update(encrypted_text1) + decryptor2.finalize()
    final_encrypted_text = encryptor3.update(decrypted_text2) + encryptor3.finalize()

    return iv + final_encrypted_text

# Decrypt data using Triple DES with three keys
# Διαχωρίζει το IV από τα κρυπτογραφημένα δεδομένα.
# Δημιουργεί τα αντίστοιχα αντικείμενα Cipher για τα τρία κλειδιά.
# Δημιουργεί τα αντίστοιχα decryptors και encryptors.
# Αποκρυπτογραφεί τα δεδομένα με το τρίτο κλειδί, κρυπτογραφεί με το δεύτερο και αποκρυπτογραφεί με το πρώτο.
# Αφαιρεί το padding από τα αποκρυπτογραφημένα δεδομένα.
def triple_des_decrypt_3keys(cipher_text, key1, key2, key3):
    iv = cipher_text[:8]
    encrypted_data = cipher_text[8:]

    cipher1 = Cipher(algorithms.TripleDES(key1), modes.CBC(iv), backend=default_backend())
    cipher2 = Cipher(algorithms.TripleDES(key2), modes.CBC(iv), backend=default_backend())
    cipher3 = Cipher(algorithms.TripleDES(key3), modes.CBC(iv), backend=default_backend())

    decryptor3 = cipher3.decryptor()
    encryptor2 = cipher2.encryptor()
    decryptor1 = cipher1.decryptor()

    decrypted_text3 = decryptor3.update(encrypted_data) + decryptor3.finalize()
    encrypted_text2 = encryptor2.update(decrypted_text3) + encryptor2.finalize()
    final_decrypted_text = decryptor1.update(encrypted_text2) + decryptor1.finalize()

    unpadder = padding.PKCS7(algorithms.TripleDES.block_size).unpadder()
    return unpadder.update(final_decrypted_text) + unpadder.finalize()

def main():
    key_file1 = 'keyfile1.key'
    key_file2 = 'keyfile2.key'
    key_file3 = 'keyfile3.key'

    # Get password from user
    password = input("Enter a password for key generation: ").strip()

    # Create and save keys
    generate_key(password, key_file1, 8)
    generate_key(password, key_file2, 8)
    generate_key(password, key_file3, 8)

    # Load keys
    key1 = load_key(key_file1, password, 8)
    key2 = load_key(key_file2, password, 8)
    key3 = load_key(key_file3, password, 8)

    # Ensure keys are 8 bytes each
    assert len(key1) == 8
    assert len(key2) == 8
    assert len(key3) == 8

    # Get message from user
    message = input("Enter the message to encrypt: ")

    # Encrypt with three keys
    encrypted_text = triple_des_encrypt_3keys(message.encode(), key1, key2, key3)
    print(f"Encrypted message: {encrypted_text.hex()}")

    # Decrypt with three keys
    decrypted_text = triple_des_decrypt_3keys(encrypted_text, key1, key2, key3)
    print(f"Decrypted message: {decrypted_text.decode()}")

if __name__ == "__main__":
    main()