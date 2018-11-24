#!/usr/bin/env python3

import click
from stream import Stream

@click.command()
@click.argument("public_key_filename", nargs=1)
@click.argument("private_key_filename", nargs=1)
@click.argument("stream_filename", nargs=1)
def create_stream(public_key_filename, private_key_filename, stream_filename):
    s = Stream()
    s.set_stream_signature_keys(public_key_filename, private_key_filename)
    s.create("test.im", { 'private-junk' : "this is user junk" } )
    s.append(bytes("There is shite here.", "utf-8"))
    s.append(bytes("Even more shit!", "utf-8"))
    s.close()

if __name__ == "__main__":
    create_stream()
