#!/usr/bin/env python3

import click
import stream

@click.command()
@click.argument("stream_filename", nargs=1)
def read_stream(stream_filename):
    try:
        with stream.Stream(stream_filename) as s:
            block_index = 1
            while True:
                block = s.read_block(block_index)
                if not block:
                    break

                print("%d: %s" % (block_index, block))
                block_index += 1

    except stream.BlockSignatureVerifyFailureException:
        print("block signature failed to verify. stop!")
        return

if __name__ == "__main__":
    read_stream()
