import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from PIL import Image
import matplotlib.pyplot as plt


# Function to load the key and salt from a file
def load_key(key_file, password, key_length=32, iterations=100000):
    with open(key_file, 'rb') as f:
        data = f.read()
        salt = data[:16]
        key = data[16:]
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                     length=key_length,
                     salt=salt,
                     iterations=iterations,
                     backend=default_backend())
    kdf.verify(password.encode('utf-8'), key)
    return key




# Function to decrypt file using ECB mode
def decrypt_file_ecb(encrypted_file, decrypted_file, key, algorithm):
    with open(encrypted_file, 'rb') as f_in, open(decrypted_file, 'wb') as f_out:
        header = f_in.read(54)  # Read the BMP header
        f_out.write(header)  # Write the BMP header to the decrypted file

        ciphertext = f_in.read()
        cipher = Cipher(algorithm(key), modes.ECB(), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithm.block_size).unpadder()
        unpadded_text = unpadder.update(decrypted_text) + unpadder.finalize()
        f_out.write(unpadded_text)
    print(f"File decrypted using ECB mode and saved to {decrypted_file}")
    return decrypted_file




# Function to decrypt file using CBC mode
def decrypt_file_cbc(encrypted_file, decrypted_file, key, algorithm, iv_length):
    with open(encrypted_file, 'rb') as f_in, open(decrypted_file, 'wb') as f_out:
        header = f_in.read(54)  # Read the BMP header
        f_out.write(header)  # Write the BMP header to the decrypted file

        iv = f_in.read(iv_length)
        cipher = Cipher(algorithm(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        ciphertext = f_in.read()
        decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithm.block_size).unpadder()
        unpadded_text = unpadder.update(decrypted_text) + unpadder.finalize()
        f_out.write(unpadded_text)
    print(f"File decrypted using CBC mode and saved to {decrypted_file}")
    return decrypted_file



# Function to decrypt file using OFB mode
def decrypt_file_ofb(encrypted_file, decrypted_file, key, algorithm, iv_length):
    with open(encrypted_file, 'rb') as f_in, open(decrypted_file, 'wb') as f_out:
        header = f_in.read(54)  # Read the BMP header
        f_out.write(header)  # Write the BMP header to the decrypted file

        iv = f_in.read(iv_length)
        cipher = Cipher(algorithm(key), modes.OFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        ciphertext = f_in.read()
        decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()
        f_out.write(decrypted_text)
    print(f"File decrypted using OFB mode and saved to {decrypted_file}")
    return decrypted_file



# Function to decrypt file using CFB mode
def decrypt_file_cfb(encrypted_file, decrypted_file, key, algorithm, iv_length):
    with open(encrypted_file, 'rb') as f_in, open(decrypted_file, 'wb') as f_out:
        header = f_in.read(54)  # Read the BMP header
        f_out.write(header)  # Write the BMP header to the decrypted file

        iv = f_in.read(iv_length)
        cipher = Cipher(algorithm(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        ciphertext = f_in.read()
        decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()
        f_out.write(decrypted_text)
    print(f"File decrypted using CFB mode and saved to {decrypted_file}")
    return decrypted_file


# Function to decrypt file using CFB mode
def decrypt_file_ctr(encrypted_file, decrypted_file, key, algorithm, iv_length):
    with open(encrypted_file, 'rb') as f_in, open(decrypted_file, 'wb') as f_out:
        header = f_in.read(54)  # Read the BMP header
        f_out.write(header)  # Write the BMP header to the decrypted file

        iv = f_in.read(iv_length)
        cipher = Cipher(algorithm(key), modes.CTR(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        ciphertext = f_in.read()
        decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()
        f_out.write(decrypted_text)
    print(f"File decrypted using CTR mode and saved to {decrypted_file}")
    return decrypted_file



# Function to visualize images
def visualize_images(original_bmp, decrypted_bmp_ecb, decrypted_bmp_cbc, decrypted_bmp_ofb, decrypted_bmp_cfb, decrypted_bmp_ctr):
    # Open the images
    original_image = Image.open(original_bmp)
    decrypted_image_ecb = Image.open(decrypted_bmp_ecb)
    decrypted_image_cbc = Image.open(decrypted_bmp_cbc)
    decrypted_image_ofb = Image.open(decrypted_bmp_ofb)
    decrypted_image_cfb = Image.open(decrypted_bmp_cfb)
    decrypted_image_ctr = Image.open(decrypted_bmp_ctr)

    # Display the images
    plt.figure(figsize=(15, 5))


    plt.subplot(1, 5, 1)
    plt.title('Decrypted Image (ECB)')
    plt.imshow(decrypted_image_ecb)

    plt.subplot(1, 5, 2)
    plt.title('Decrypted Image (CBC)')
    plt.imshow(decrypted_image_cbc)

    plt.subplot(1, 5, 3)
    plt.title('Decrypted Image (OFB)')
    plt.imshow(decrypted_image_ofb)

    plt.subplot(1, 5, 4)
    plt.title('Decrypted Image (CFB)')
    plt.imshow(decrypted_image_cfb)
    
    plt.subplot(1, 5, 5)
    plt.title('Decrypted Image (CTR)')
    plt.imshow(decrypted_image_ctr)

    plt.show()




def main():
    key_file = 'keyfile.key'

    encrypted_file_ecb = 'security-ecb.bmp'
    decrypted_file_ecb = 'decrypted-ecb.bmp'

    encrypted_file_cbc = 'security-cbc.bmp'
    decrypted_file_cbc = 'decrypted-cbc.bmp'

    encrypted_file_ofb = 'security-ofb.bmp'
    decrypted_file_ofb = 'decrypted-ofb.bmp'

    encrypted_file_cfb = 'security-cfb.bmp'
    decrypted_file_cfb = 'decrypted-cfb.bmp'
    
    encrypted_file_ctr = 'security-ctr.bmp'
    decrypted_file_ctr = 'decrypted-ctr.bmp'

    # Get password from user
    password = input("Enter the password: ").strip()

    # Load the key
    key = load_key(key_file, password)

    # Decrypt the encrypted BMP file using ECB mode
    decrypted_bmp_ecb = decrypt_file_ecb(encrypted_file_ecb, decrypted_file_ecb, key, algorithms.AES)

    # Decrypt the encrypted BMP file using CBC mode
    decrypted_bmp_cbc = decrypt_file_cbc(encrypted_file_cbc, decrypted_file_cbc, key, algorithms.AES, 16)

    # Decrypt the encrypted BMP file using OFB mode
    decrypted_bmp_ofb = decrypt_file_ofb(encrypted_file_ofb, decrypted_file_ofb, key, algorithms.AES, 16)

    # Decrypt the encrypted BMP file using CFB mode
    decrypted_bmp_cfb = decrypt_file_cfb(encrypted_file_cfb, decrypted_file_cfb, key, algorithms.AES, 16)
    
    # Decrypt the encrypted BMP file using CTR mode
    decrypted_bmp_ctr = decrypt_file_ctr(encrypted_file_ctr, decrypted_file_ctr, key, algorithms.AES, 16)

    # Visualize the original and decrypted images
    visualize_images(encrypted_file_ecb, decrypted_bmp_ecb, decrypted_bmp_cbc, decrypted_bmp_ofb, decrypted_bmp_cfb, decrypted_bmp_ctr)


if __name__ == "__main__":
    main()