# Cryptography project explanation and viva guide

## Project 2 abstract

Cryptography Algorithms Implementation is a Python application demonstrating
confidentiality and integrity through AES-256-GCM, asymmetric key usage through
RSA-OAEP hybrid encryption, and file fingerprints through SHA-256. Users can
encrypt and restore files, generate password-protected RSA keys, and observe how
wrong passwords or modified ciphertext are rejected. Established library
primitives are used rather than custom cryptographic arithmetic.

### Architecture

AES: password + random salt → scrypt → AES key; plaintext + fresh nonce →
authenticated ciphertext → JSON envelope → matching password → plaintext.

RSA hybrid: random AES key → encrypt file; RSA public key → wrap AES key;
matching RSA private key → unwrap AES key → decrypt and authenticate file.

Hashing: text/file bytes → SHA-256 → 64-character hexadecimal digest.

### Viva practice

**What is symmetric encryption?** The same secret key encrypts and decrypts data.
AES is the example here.

**What is asymmetric encryption?** A related public/private key pair is used.
Here a public key wraps the AES key and the matching private key unwraps it.

**Why AES-GCM?** It authenticates ciphertext as well as encrypting it. Modified
ciphertext or incorrect parameters fail the authentication check.

**What is a nonce?** A value used once per key. Reusing an AES-GCM nonce with the
same key can break security. The code creates a fresh random 12-byte nonce.

**What is a salt?** A random value used in password-based key derivation so equal
passwords do not automatically produce equal derived keys across encryptions.

**Why use scrypt?** It derives a cryptographic key from a password with a
computational and memory cost. This demo fixes its parameters instead of accepting
arbitrary cost values from untrusted files.

**Why hybrid RSA?** Direct RSA can encrypt only a short message (190 bytes for a
2048-bit RSA key with OAEP/SHA-256). AES encrypts file data efficiently, while RSA
wraps only the 32-byte AES key.

**Is Base64 encryption?** No. It is a reversible text encoding for binary bytes.

**Is SHA-256 reversible?** No. It is one-way hashing, not encryption.

**Does hashing authenticate a sender?** Not on its own. The expected digest must
come from a trusted source, or a MAC/signature is needed.

**Did you implement the underlying mathematical algorithms?** No. I built and
integrated the application using the cryptography library's AES/RSA primitives,
including validation, file handling, key protection, and tests.

