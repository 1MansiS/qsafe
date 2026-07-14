"""Synthetic Python file with classical crypto primitives for scanner testing."""

import hashlib
from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import AES, DES3, ARC4
from Crypto.Hash import MD5, SHA1
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# RSA key generation (PyCryptodome) — quantum-vulnerable
def gen_rsa_pycryptodome():
    key = RSA.generate(1024)
    return key


# RSA key generation (cryptography lib) — quantum-vulnerable
def gen_rsa_cryptography():
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    return key


# ECDH key generation (cryptography lib) — quantum-vulnerable
def gen_ecdh():
    key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    return key


# AES-ECB (PyCryptodome) — insecure mode
def aes_ecb_pycryptodome(key, data):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)


# AES-ECB (cryptography lib) — insecure mode
def aes_ecb_cryptography(key, data):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


# 3DES (PyCryptodome) — deprecated
def triple_des_pycryptodome(key, data):
    cipher = DES3.new(key, DES3.MODE_CBC)
    return cipher.encrypt(data)


# 3DES (cryptography lib) — deprecated
def triple_des_cryptography(key, nonce, data):
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


# RC4 (PyCryptodome) — broken
def rc4_pycryptodome(key, data):
    cipher = ARC4.new(key)
    return cipher.encrypt(data)


# RC4 (cryptography lib) — broken
def rc4_cryptography(key, data):
    cipher = Cipher(algorithms.ARC4(key), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


# Blowfish — deprecated, 64-bit block (SWEET32)
def blowfish_cryptography(key, nonce, data):
    cipher = Cipher(algorithms.Blowfish(key), modes.CBC(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


# MD5 — collision-broken
def hash_md5(data):
    return hashlib.md5(data).hexdigest()


# SHA-1 — deprecated
def hash_sha1(data):
    return hashlib.sha1(data).hexdigest()
