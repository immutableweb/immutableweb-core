#!/usr/bin/env python3

import click
import stream

@click.command()
@click.argument("public_key_filename", nargs=1)
@click.argument("stream_filename", nargs=1)
def read_stream(public_key_filename, stream_filename):
    s = stream.Stream()
    s.set_stream_signature_keys(public_key_filename, None)

    block_index = 1
    try:
        s.open(stream_filename)
        while True:
            block = s.read_block(block_index)
            if not block:
                break

            print("%d: %s" % (block_index, block))
            block_index += 1

    except stream.BlockSignatureVerifyFailureException:
        print("block signature failed to verify. stop!")
        return

    s.close()

if __name__ == "__main__":
    read_stream()
