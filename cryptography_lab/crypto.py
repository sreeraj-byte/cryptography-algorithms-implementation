"""Educational crypto application built on the maintained cryptography library."""
import base64
import binascii
import hashlib
import json
import os
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAX_BYTES = 10 * 1024 * 1024
AAD = b'codec-internship-lab:v1'


def b64(data):
    return base64.b64encode(data).decode('ascii')


def unb64(value):
    if not isinstance(value, str):
        raise ValueError('Invalid Base64 field.')
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError('Invalid Base64 field.') from error


def check_data(data):
    if len(data) > MAX_BYTES:
        raise ValueError('Use files of 10 MiB or smaller in this learning project.')


def password_bytes(password):
    if len(password) < 12:
        raise ValueError('Use a password of at least 12 characters.')
    return password.encode('utf-8')


def derive(password, salt):
    return Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(password_bytes(password))


def parse_envelope(raw, algorithm):
    if len(raw) > MAX_BYTES * 2:
        raise ValueError('Envelope too large.')
    try:
        data = json.loads(raw)
    except (ValueError, TypeError) as error:
        raise ValueError('Invalid encrypted JSON envelope.') from error
    if not isinstance(data, dict) or data.get('version') != 1 or data.get('algorithm') != algorithm:
        raise ValueError('Unsupported envelope version or algorithm.')
    nonce = unb64(data.get('nonce'))
    ciphertext = unb64(data.get('ciphertext'))
    if len(nonce) != 12 or not 16 <= len(ciphertext) <= MAX_BYTES + 16:
        raise ValueError('Invalid nonce or ciphertext length.')
    return data, nonce, ciphertext


def aes_encrypt(data, password):
    check_data(data)
    salt, nonce = os.urandom(16), os.urandom(12)
    ciphertext = AESGCM(derive(password, salt)).encrypt(nonce, data, AAD)
    return json.dumps(dict(version=1, algorithm='AES-256-GCM', kdf='scrypt-n16384-r8-p1',
                           salt=b64(salt), nonce=b64(nonce), ciphertext=b64(ciphertext)), indent=2).encode()


def aes_decrypt(envelope, password):
    data, nonce, ciphertext = parse_envelope(envelope, 'AES-256-GCM')
    salt = unb64(data.get('salt'))
    if len(salt) != 16 or data.get('kdf') != 'scrypt-n16384-r8-p1':
        raise ValueError('Unsupported password derivation parameters.')
    try:
        return AESGCM(derive(password, salt)).decrypt(nonce, ciphertext, AAD)
    except InvalidTag as error:
        raise ValueError('Decryption failed: wrong password or modified data.') from error


def generate_rsa_keys(password):
    secret = password_bytes(password)
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.BestAvailableEncryption(secret))
    public_pem = private.public_key().public_bytes(serialization.Encoding.PEM,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo)
    return private_pem, public_pem


def oaep():
    return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def rsa_encrypt(data, public_pem):
    check_data(data)
    public = serialization.load_pem_public_key(public_pem)
    if not isinstance(public, rsa.RSAPublicKey) or public.key_size < 2048:
        raise ValueError('Provide an RSA public key with at least 2048 bits.')
    key, nonce = AESGCM.generate_key(bit_length=256), os.urandom(12)
    return json.dumps(dict(version=1, algorithm='RSA-OAEP-SHA256+AES-256-GCM',
                           wrapped_key=b64(public.encrypt(key, oaep())), nonce=b64(nonce),
                           ciphertext=b64(AESGCM(key).encrypt(nonce, data, AAD))), indent=2).encode()


def rsa_decrypt(envelope, private_pem, password):
    data, nonce, ciphertext = parse_envelope(envelope, 'RSA-OAEP-SHA256+AES-256-GCM')
    private = serialization.load_pem_private_key(private_pem, password=password_bytes(password))
    if not isinstance(private, rsa.RSAPrivateKey) or private.key_size < 2048:
        raise ValueError('Provide an encrypted RSA private key with at least 2048 bits.')
    wrapped = unb64(data.get('wrapped_key'))
    if len(wrapped) != (private.key_size + 7) // 8:
        raise ValueError('Invalid wrapped key length.')
    try:
        key = private.decrypt(wrapped, oaep())
        return AESGCM(key).decrypt(nonce, ciphertext, AAD)
    except (ValueError, InvalidTag) as error:
        raise ValueError('Decryption failed: wrong key or modified data.') from error


def sha256(data):
    return hashlib.sha256(data).hexdigest()
