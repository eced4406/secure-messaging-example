#!/usr/bin/env python3

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, utils

SECRET_KEY = b"_pprJ1zbEubfXFAv0w8wdESGViyjo5uB6wbsxYZV9dc="


def load_file(filename):
    with open(filename, "rb") as infile:
        return infile.read()


def decrypt_message(message, key):
    f = Fernet(key)
    return f.decrypt(message)


def generate_hash(input):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(input)
    return digest.finalize()


def verify_signature(verify_key_filename, digest, signature):
    with open(verify_key_filename, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
        )
        public_key.verify(
            signature,
            digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            utils.Prehashed(hashes.SHA256()),
        )


ciphertext = load_file("ciphertext.dat")
signature = load_file("signature.dat")
digest = generate_hash(ciphertext)
verify_signature("public.pem", digest, signature)
plaintext = decrypt_message(ciphertext, SECRET_KEY)
print(plaintext.decode('utf-8'), end="")