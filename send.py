#!/usr/bin/env python3

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, utils

SECRET_KEY = b"_pprJ1zbEubfXFAv0w8wdESGViyjo5uB6wbsxYZV9dc="


def load_message(filename):
    with open(filename, "rb") as infile:
        return infile.read()


def encrypt_message(message, key):
    f = Fernet(key)
    return f.encrypt(message)


def generate_hash(input):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(input)
    return digest.finalize()


def generate_signature(signing_key_filename, digest):
    with open(signing_key_filename, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )

        return private_key.sign(
            digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            utils.Prehashed(hashes.SHA256()),
        )


plaintext = load_message("plaintext.dat")
ciphertext = encrypt_message(plaintext, SECRET_KEY) # confidentiality
digest = generate_hash(ciphertext) # integrity
signature = generate_signature("private.pem", digest) # authenticity

with open("ciphertext.dat", "wb") as cipher_file:
    cipher_file.write(ciphertext)

with open("signature.dat", "wb") as sig_file:
    sig_file.write(signature)
