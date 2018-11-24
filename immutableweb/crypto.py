import sys
import os
import struct
from hashlib import sha256
import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

from immutableweb import exception as exc

KEY_VERIFICATION_TEST_MESSAGE = "stop tectonic drift!"

def make_key_pair():
    private_key = rsa.generate_private_key(
         public_exponent=65537,
         key_size=2048,
         backend=default_backend())

    public_key = private_key.public_key()

    return (private_key, public_key)


def get_private_key_pem(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption())

def get_public_key_pem(public_key):
    return public_key.public_bytes(
       encoding=serialization.Encoding.PEM,
       format=serialization.PublicFormat.SubjectPublicKeyInfo)


def load_private_key(filename):
    with open(filename, "rb") as key_file:
         private_key = serialization.load_pem_private_key(
             key_file.read(),
             password=None,
             backend=default_backend())
    return private_key


def load_public_key(filename):
    with open(filename, "rb") as key_file:
         public_key = serialization.load_pem_public_key(
             key_file.read(),
             backend=default_backend())
    return public_key


def serialize_public_key(key):
    pem = key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)

    return pem.decode('utf-8')


def deserialize_public_key(pem):
    public_key = serialization.load_pem_public_key(
        pem,
        backend=default_backend())

    return public_key


def validate_key_pair(private_key, public_key):
    '''
        Does a round-trip encryption in order to ensure that the provided
        keys actually work as expected.
    '''

    msg = bytes(KEY_VERIFICATION_TEST_MESSAGE, 'utf-8')
    try:
        encrypted = public_key.encrypt(
            msg,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None))
        decrypted = private_key.decrypt(
            encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None))
        if msg != decrypted:
            raise exc.InvalidKeyPair

    except ValueError:
        raise exc.InvalidKeyPair


def sign(private_key, block):
    return private_key.sign(
        block,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256())


def verify(public_key, block, signature):
    try:
        signature = public_key.verify(
            signature,
            block,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256())
    except InvalidSignature:
        raise exc.BlockSignatureVerifyFailureException
