#!/usr/bin/env python3

import sys
import os
import click

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

@click.command()
@click.option('--force', default=False, help='Overwrite keys if they exist')
@click.argument("base_filename", nargs=1)
def make_keys(force, base_filename):

    private_key = rsa.generate_private_key(
         public_exponent=65537,
         key_size=2048,
         backend=default_backend())

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption())

    private_filename = base_filename + "-private.pem"
    public_filename = base_filename + "-public.pem"
    if os.path.exists(private_filename) and not force:
        print("key %s exists. Use --force to overwrite.", private_filename)
        return

    if os.path.exists(public_filename) and not force:
        print("key %s exists. Use --force to overwrite.", public_filename)
        return

    with open(base_filename + "-private.pem", "w") as f:
        f.write(pem.decode("utf-8")),

    public_key = private_key.public_key()
    pem = public_key.public_bytes(
           encoding=serialization.Encoding.PEM,
           format=serialization.PublicFormat.SubjectPublicKeyInfo)

    with open(base_filename + "-public.pem", "w") as f:
        f.write(pem.decode("utf-8")),

def usage(command):
    with click.Context(command) as ctx:
        click.echo(command.get_help(ctx))

if __name__ == "__main__":
    make_keys()
    
