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
                metadata, content = s.read_block(block_index)
                if not content:
                    break

                print("%d: %s" % (block_index, content))
                block_index += 1

    except stream.BlockSignatureVerifyFailureException:
        print("block signature failed to verify. stop!")
        return

if __name__ == "__main__":
    read_stream()
