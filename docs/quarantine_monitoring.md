# Secure Quarantine Implementation

## Overview
The legacy file-copy routine has been replaced with a robust encryption pipeline. Each file passed to the `QuarantineManager` is now uniquely encrypted using AES-256 in CBC mode, paired with PKCS#7 padding to handle arbitrary file sizes securely.

## Key Management
- **Unique Keys**: For every file processed, a unique 256-bit encryption key, a 128-bit Initialization Vector (IV), and a 256-bit HMAC key are generated via `secrets.token_bytes()`.
- **SQLite Keystore**: A restricted SQLite table (`keystore.db`) dynamically maps a generated `file_ref` (a 16-byte hex token) to the file's specific cryptographic material.
- **Permissions**: The database permissions are aggressively restricted upon initialization (`os.chmod(0o600)`).

## Tamper Resistance
- **Encrypt-then-MAC**: An HMAC (SHA-256) signature is calculated continuously over the ciphertext chunks during the encryption process and appended to the end of the encrypted file (`q_{file_ref}.bin`).
- **Pre-decryption Validation**: During decryption, the system pre-computes the HMAC across the ciphertext payload *before* attempting AES decryption. If the signature doesn't match exactly, the decryption aborts immediately with an `HMAC verification failed` exception.

## Memory Security
- **Zeroization**: All cryptographic material is held in mutable `bytearray` objects and is sequentially zeroized post-execution to prevent the keys from lingering inside memory dumps.
