# AES Encryption in Python

**Course**: Cryptography  
**Student**: Panagiota Vinni 
**Assignment**: Lab Exercise 2 - AES Encryption  
**Semester**: 2nd  

---

## Table of Contents

1. [Overview](#overview)
2. [Objective](#objective)
3. [Algorithm Description](#algorithm-description)
4. [Files](#files)
5. [Setup and Dependencies](#setup-and-dependencies)
6. [Usage Instructions](#usage-instructions)
7. [Conclusion](#conclusion)

---

## Overview

This project involves encrypting the contents of a file using the **AES encryption algorithm** in **CBC mode** with **PKCS#7 padding**. The encryption key was generated in a previous assignment and is stored in a file. This program can also optionally accept three parameters: the key file, the input file, and the output file.

---

## Objective

The main objectives of this assignment are:

- To encrypt a file using the AES algorithm with a key and IV.
- To analyze the size of the encrypted file and understand why it is always larger than the input.
- To experiment with encryption without padding and observe its effects.

---

## Algorithm Description

### AES (Advanced Encryption Standard)

AES is a symmetric encryption algorithm that uses a single key for both encryption and decryption. The project utilizes **AES in CBC mode**, which requires an **initialization vector (IV)** for encryption. The IV ensures that identical plaintext blocks result in different ciphertext blocks, enhancing security.

### Padding

PKCS#7 padding is used to make the size of the plaintext a multiple of the block size (16 bytes for AES). Without padding, the encryption process could fail for non-multiples of the block size.

---

## Files

- **key.txt**: File containing the AES encryption key.
- **input.txt**: Input file to be encrypted.
- **output.txt**: Encrypted output file.

---

## Setup and Dependencies

To run this project, the following Python libraries are required:

- `cryptography`

You can install the necessary libraries using:

```bash
pip install cryptography
```

---

## Usage Instructions
1. Encrypting a File:
   - Run the Python script with optional parameters:
     ```python
      python encrypt.py key.txt input.txt output.txt
      ```
   - If no parameters are provided, the program will prompt for input and output files.
     
2. Decryption:
   - To decrypt an encrypted file, provide the encrypted file, the key, and the output file for the plaintext:
      ```python
      python decrypt.py key.txt encrypted_file.txt output.txt
      ```
   
---

## Conclusion
This project demonstrates how AES encryption can be implemented in Python for secure file handling. By experimenting with different encryption settings and analyzing file sizes, we gain a deeper understanding of how symmetric encryption functions in real-world applications.
