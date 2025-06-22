# FileCryptor
### File Encryption Decryption app

A lightweight Java Swing desktop application that allows users to securely encrypt and decrypt files using AES encryption. Built with simplicity and usability in mind, it features drag-and-drop support, password-based encryption with PBKDF2 key derivation, and multithreaded file processing.

This project is ideal for securing sensitive documents or learning how cryptographic operations work in desktop applications.

## Features

- AES (CBC mode) encryption and decryption for strong security
- PBKDF2 with HMAC-SHA256 for password-based key derivation
- Random salt and IV generation for each encryption
- Drag-and-drop UI for easy file input
- Multithreaded file handling with ExecutorService
- Clean GUI with real-time logs

## Installation and Running the Application

### Requirements
- Java 8 or higher
- A desktop operating system that supports Java Swing

### Compile and Run
```bash
javac FileEncryptionApp.java
java FileEncryptionApp
```

Alternatively, export as a `.jar` file using an IDE like IntelliJ or Eclipse and launch it directly.

## Security Details

- **Encryption Algorithm**: AES (Advanced Encryption Standard)
- **Mode**: CBC (Cipher Block Chaining)
- **Padding**: PKCS5Padding
- **Key Derivation**: PBKDF2WithHmacSHA256 (64,000+ iterations)
- **Salt**: 128-bit random salt per encryption
- **IV**: 128-bit random IV per file

Each encrypted file stores the salt and IV prepended to the actual ciphertext to allow secure decryption.

## How It Works

1. User drags and drops a file into the app.
2. App prompts for a password.
3. A 256-bit AES key is derived using PBKDF2 and a random salt.
4. A random IV is generated.
5. The file is encrypted and saved as `filename.ext.enc` with salt and IV prepended.
6. For decryption, the app reads the salt and IV from the encrypted file, derives the key, and restores the original file.
7. Output files are saved in the same directory as the original file.

## Tech Stack

- Language: Java
- UI Toolkit: Swing
- Concurrency: ExecutorService
- Cryptography APIs: javax.crypto, java.security
