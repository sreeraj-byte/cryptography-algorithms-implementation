# Cryptography Algorithms Implementation

Independent Python internship project with its own dashboard and command-line tool.

## Start here

You need a **Windows, macOS, or Linux computer with Python 3.11 or newer**.
A phone can download the ZIP but is not the intended environment for running it.
Extract the ZIP and open a terminal in `cryptography_algorithms`.

### Windows (Command Prompt)

```bat
python -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
python -m streamlit run app.py --server.address 127.0.0.1 --browser.gatherUsageStats false
```

If `python` is not found, try `py` for the first command after installing Python.

### macOS / Linux

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m streamlit run app.py --server.address 127.0.0.1 --browser.gatherUsageStats false
```

Open **http://127.0.0.1:8501** if a browser does not open automatically.
Keep the terminal running. Press Ctrl+C there to stop the dashboard.
Internet is needed for initial package installation; the demos then run locally.

## Project 2 — Cryptography Algorithms Implementation

**Objective:** Understand symmetric encryption, asymmetric encryption, and
one-way hashing by working with real files.

**Implemented:**

- **AES-256-GCM:** Encrypt/decrypt a file with a password-derived key. Scrypt uses
  a fresh random 16-byte salt; AES-GCM uses a fresh 12-byte nonce and authenticates
  the ciphertext. Wrong passwords and tampering fail decryption.
- **RSA hybrid encryption:** Generate 2048-bit keys, protect the private PEM with
  a password, wrap a fresh AES key with RSA-OAEP/SHA-256, and encrypt file contents
  with AES-256-GCM. Hybrid encryption handles files beyond RSA's direct input limit.
- **SHA-256:** Hash text or files and optionally compare an expected hash.
- JSON encrypted envelopes, Base64 binary encoding, downloadable outputs.
- Exclusive output creation in the CLI to prevent accidental overwrites.

This implements an application **using established cryptographic algorithms**;
it does not implement AES rounds or RSA arithmetic from scratch. The maintained
`cryptography` library is used instead of the original PyCrypto toolkit.
SHA-256 is a one-way hash; it cannot be decrypted and is not suitable by itself
for storing passwords. A matching hash proves equality to the provided reference,
not that an untrusted file is safe.

### Dashboard demonstration

1. Open this project's dashboard and select **AES-256-GCM**.
2. Upload `sample_message.txt`, enter and confirm a 12+ character password, and
   click **Encrypt file**. Download `encrypted.json`.
3. Select **Decrypt**, upload `encrypted.json`, enter the same password, and
   download `decrypted.bin`. Open it as text or rename it to `.txt`.
4. Repeat with the wrong password to demonstrate failure.
5. Select **RSA hybrid**, generate/download the key pair, and encrypt the same
   sample using the generated public key. Decrypt using the matching private key.
6. Select **SHA-256**, hash a message, change one character, and hash it again.

Files up to 10 MiB are supported (encrypted JSON inputs up to 20 MiB). The original
filename is not stored in encrypted envelopes, so restored files use a generic
name. Passwords must contain at least 12 characters. Use a long, unique passphrase.
Keys are generated at runtime; no private keys or real passwords are bundled.
Generated dashboard keys/results remain in the active session. Download needed
outputs, then use **Clear cryptography session data** and stop the app.

### Command-line AES workflow

Passwords are prompted without echo; do not put them into command history.

```sh
python -m cryptography_lab.cli aes-encrypt sample_message.txt message.aes.json
python -m cryptography_lab.cli aes-decrypt message.aes.json restored.txt
python -m cryptography_lab.cli sha256 sample_message.txt
python -m cryptography_lab.cli sha256 restored.txt
```

The two file hashes should match.

### Command-line RSA workflow

```sh
python -m cryptography_lab.cli rsa-keygen --private private.pem --public public.pem
python -m cryptography_lab.cli rsa-encrypt sample_message.txt message.rsa.json --key public.pem
python -m cryptography_lab.cli rsa-decrypt message.rsa.json restored-rsa.txt --key private.pem
```

The private key's password is required for decryption. Share a public key only;
keep the private key and its password confidential. File permissions on Windows
are governed by Windows ACLs; the Unix private-key mode is 0600.

This local learning tool does not provide key rotation, certificate validation,
sender identity/signatures, secure key distribution, or production key custody.
RSA hybrid encryption alone does not authenticate the sender. Do not treat this
portfolio application as an audited production security product.


## Run automated checks

```sh
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

See `PROJECT_GUIDE.md` for explanations and viva practice and `VALIDATION.md` for
checks executed. `tested_versions.txt` lists the direct versions used.
