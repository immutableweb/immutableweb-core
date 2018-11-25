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
    '''
        This function generates a new set of RSA crypto keys. Returns private and public keys in a tuple.
    '''
    private_key = rsa.generate_private_key(
         public_exponent=65537,
         key_size=2048,
         backend=default_backend())

    public_key = private_key.public_key()

    return (public_key, private_key)


def get_private_key_pem(private_key):
    '''
        Generate an ASCII pem string from a private key.
    '''

    if not private_key:
        raise exc.missingKey

    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption())

def get_public_key_pem(public_key):
    '''
        Generate an ASCII pem string from a public key.
    '''

    if not public_key:
        raise exc.missingKey

    return public_key.public_bytes(
       encoding=serialization.Encoding.PEM,
       format=serialization.PublicFormat.SubjectPublicKeyInfo)


def load_private_key(filename):
    '''
        Load a private key off disk, given a filename that contains a private key.
    '''

    if not filename:
        raise ValueError("Must provide private key file.")

    with open(filename, "rb") as key_file:
         private_key = serialization.load_pem_private_key(
             key_file.read(),
             password=None,
             backend=default_backend())
    return private_key


def load_public_key(filename):
    '''
        Load a public key off disk, given a filename that contains a public key.
    '''

    if not filename:
        raise ValueError("Must provide public key file.")

    with open(filename, "rb") as key_file:
         public_key = serialization.load_pem_public_key(
             key_file.read(),
             backend=default_backend())
    return public_key


def serialize_public_key(key):
    '''
        Serialize public key to ASCII.
    '''

    if not key:
        raise exc.missingKey

    pem = key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)

    return pem.decode('utf-8')


def deserialize_public_key(pem):
    '''
        Deserialize public key from ASCII.
    '''

    if not pem:
        raise exc.missingKey("Missing pem data")

    public_key = serialization.load_pem_public_key(
        pem,
        backend=default_backend())

    return public_key


def validate_key_pair(public_key, private_key):
    '''
        Does a round-trip encryption in order to ensure that the provided
        keys actually work as expected. Throws Missing Key or exc.InvalidKeyPair
    '''

    if not private_key or not public_key:
        raise esc.MissingKey("Both private and public key must be provided.")

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
    '''
        Sign the given block with the given private key.
    '''

    if not private_key:
        raise exc.missingKey("Missing private key")

    return private_key.sign(
        block,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256())


def verify(public_key, block, signature):
    '''
        Verify the given block with the given public key.
    '''

    if not public_key:
        raise exc.missingKey("Missing public key")

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


def encrypt(public_key, block):
    '''
        Encrypt the given block with the given public key. Return encrypted block.
    '''

    if not public_key:
        raise exc.missingKey("Missing public key")

    return public_key.encrypt(
        block,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None))


def decrypt(private_key, block):
    '''
        Decrypt the given block with the given private key. Return decrypted block.
    '''

    if not private_key:
        raise exc.missingKey("Missing private key")

    return private_key.decrypt(
        block,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None))
