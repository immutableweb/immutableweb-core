#!/usr/bin/env python3

import sys
import os
import click

from immutableweb import stream
from immutableweb import crypto
from immutableweb import exception as exc

@click.command()
@click.option('--force', default=False, help='Overwrite keys if they exist')
@click.argument("base_filename", nargs=1)
def make_keys(force, base_filename):

    public_key, private_key = crypto.make_key_pair()
    pem = crypto.get_private_key_pem(private_key)

    private_filename = base_filename + "-private.pem"
    public_filename = base_filename + "-public.pem"
    if os.path.exists(private_filename) and not force:
        print("key %s exists. Use --force to overwrite." % private_filename)
        return

    if os.path.exists(public_filename) and not force:
        print("key %s exists. Use --force to overwrite." % public_filename)
        return

    with open(base_filename + "-private.pem", "w") as f:
        f.write(pem.decode("utf-8")),

    pem = crypto.get_public_key_pem(public_key)
    with open(base_filename + "-public.pem", "w") as f:
        f.write(pem.decode("utf-8")),

def usage(command):
    with click.Context(command) as ctx:
        click.echo(command.get_help(ctx))

if __name__ == "__main__":
    make_keys()
