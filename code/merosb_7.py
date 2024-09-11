import os
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Dictionary to hold different ciphers and their key sizes
ciphers = {
    'AES': (algorithms.AES, 32, 16),  # 256-bit key and 128-bit IV
    '3DESede': (algorithms.TripleDES, 24, 8),  # 192-bit key and 64-bit IV
    'Blowfish': (algorithms.Blowfish, 16, 8),  # 128-bit key and 64-bit IV
    'RC2': (algorithms.ARC4, 16, 0),  # 128-bit key, no IV for stream cipher
}

def generate_key_iv(algorithm, key_size, iv_size):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_size + iv_size,
        salt=salt,
        iterations=100000,  # Adjust the number of iterations as needed for security
        backend=default_backend()
    )
    key_iv = kdf.derive(b"password")  # Use a strong password here instead of "password"
    key = key_iv[:key_size]
    iv = key_iv[key_size:key_size + iv_size] if iv_size > 0 else None
    return key, iv

# δημιουργεί ένα αντικείμενο Cipher για τον καθορισμένο αλγόριθμο. Εάν ο αλγόριθμος είναι ARC4 (ένα stream cipher), δεν χρειάζεται IV. 
# Για τους υπόλοιπους αλγόριθμους, χρησιμοποιείται το CBC (Cipher Block Chaining) mode που απαιτεί IV.
def create_cipher(algorithm, key, iv):
    if algorithm == algorithms.ARC4:
        return Cipher(algorithm(key), mode=None, backend=default_backend())
    else:
        return Cipher(algorithm(key), modes.CBC(iv), backend=default_backend())

def encrypt_data(cipher, data, block_size):
    if isinstance(cipher.algorithm, algorithms.ARC4):
        encryptor = cipher.encryptor()
        return encryptor.update(data)
    else:
        padder = padding.PKCS7(block_size * 8).padder()
        padded_data = padder.update(data) + padder.finalize()
        encryptor = cipher.encryptor()
        return encryptor.update(padded_data) + encryptor.finalize()

# μετρά τον χρόνο που απαιτείται για την κρυπτογράφηση δεδομένων με ένα συγκεκριμένο αλγόριθμο. Δημιουργεί το κλειδί και το IV, δημιουργεί το αντικείμενο Cipher, 
# και κρυπτογραφεί τα δεδομένα πολλές φορές (iterations). 
# Καταγράφει τον συνολικό χρόνο που απαιτήθηκε για τις κρυπτογραφήσεις και τον επιστρέφει.
def benchmark_cipher(algorithm_name, algorithm, key_size, iv_size, block_size, iterations):
    key, iv = generate_key_iv(algorithm, key_size, iv_size)
    cipher = create_cipher(algorithm, key, iv)
    data = os.urandom(block_size)

    # Warm-up encryptions
    for _ in range(2):
        encrypt_data(cipher, data, block_size)

    start_time = time.time()
    for _ in range(iterations):
        encrypt_data(cipher, data, block_size)
    end_time = time.time()

    total_time = end_time - start_time
    return total_time

def main():
    block_sizes = [16, 32, 64, 256, 1024, 8192]
    iterations = 10000000
    results = []

    for block_size in block_sizes:
        for cipher_name, (algorithm, key_size, iv_size) in ciphers.items():
            time_taken = benchmark_cipher(cipher_name, algorithm, key_size, iv_size, block_size, iterations)
            results.append((cipher_name, block_size, time_taken))
            print(f"Cipher: {cipher_name}, Block size: {block_size} bytes, Time taken: {time_taken:.2f} seconds")

    # Printing the results in a readable format
    for result in results:
        print(f"Cipher: {result[0]}, Block size: {result[1]} bytes, Time taken: {result[2]:.2f} seconds")

if __name__ == "__main__":
    main()
    
    
# Αυτό το λεξικό περιέχει τέσσερις διαφορετικούς αλγορίθμους κρυπτογράφησης:
# AES με κλειδί 256-bit και IV 128-bit.
# 3DES (Triple DES) με κλειδί 192-bit και IV 64-bit.
# Blowfish με κλειδί 128-bit και IV 64-bit.
# RC2 (που χρησιμοποιεί τον αλγόριθμο ARC4) με κλειδί 128-bit και χωρίς IV (είναι stream cipher).

# generate
# Αυτή η συνάρτηση δημιουργεί ένα κλειδί και ένα IV (Initialization Vector) χρησιμοποιώντας το PBKDF2HMAC με το αλγόριθμο SHA-256. 
# Η συνάρτηση παίρνει τον αλγόριθμο, το μέγεθος του κλειδιού και το μέγεθος του IV και επιστρέφει το κλειδί και το IV.

# create cipher
# Αυτή η συνάρτηση δημιουργεί ένα αντικείμενο Cipher για τον καθορισμένο αλγόριθμο. Εάν ο αλγόριθμος είναι ARC4 (ένα stream cipher), δεν χρειάζεται IV. 
# Για τους υπόλοιπους αλγόριθμους, χρησιμοποιείται το CBC (Cipher Block Chaining) mode που απαιτεί IV.

# encrypt data
# Αυτή η συνάρτηση κρυπτογραφεί δεδομένα χρησιμοποιώντας το αντικείμενο Cipher που δημιουργήθηκε προηγουμένως. Αν ο αλγόριθμος είναι ARC4, απλώς κρυπτογραφεί τα δεδομένα χωρίς padding. 
# Για τους υπόλοιπους αλγόριθμους, χρησιμοποιεί padding PKCS7 πριν την κρυπτογράφηση.

# benchmark_cipher
# Αυτή η συνάρτηση μετρά τον χρόνο που απαιτείται για την κρυπτογράφηση δεδομένων με ένα συγκεκριμένο αλγόριθμο. Δημιουργεί το κλειδί και το IV, δημιουργεί το αντικείμενο Cipher, 
# και κρυπτογραφεί τα δεδομένα πολλές φορές (iterations). Καταγράφει τον συνολικό χρόνο που απαιτήθηκε για τις κρυπτογραφήσεις και τον επιστρέφει.

# Η συνάρτηση main δοκιμάζει διαφορετικά μεγέθη μπλοκ (block sizes) και κρυπτογραφικούς αλγόριθμους. Για κάθε συνδυασμό, καλεί τη συνάρτηση benchmark_cipher και καταγράφει τα αποτελέσματα. 
# Τέλος, εκτυπώνει τα αποτελέσματα με τον χρόνο που απαιτήθηκε για κάθε κρυπτογραφικό αλγόριθμο και μέγεθος μπλοκ.

# Συνοψίζοντας
# Ο κώδικας αυτός δημιουργεί κλειδιά και IVs, κρυπτογραφεί δεδομένα χρησιμοποιώντας διάφορους αλγόριθμους, και μετρά τον χρόνο που απαιτείται για την κρυπτογράφηση. 
# Στη συνέχεια, καταγράφει και εκτυπώνει τα αποτελέσματα για να συγκρίνει την απόδοση διαφορετικών αλγόριθμων κρυπτογράφησης.