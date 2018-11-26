#!/usr/bin/env python3
from immutableweb import stream
from immutableweb import crypto
from nose.tools import assert_equals

class TestCreateAndVerifyStream:

    def test_create_and_verify(self):
        blocks = [b"random", b"crap"]
        s = stream.Stream()
        s.set_stream_signature_keys(crypto.make_key_pair())
        s.create("__test.iw", force=True)
        for b in blocks:
            s.append(content=b)
        s.close()

        reads = []
        with stream.Stream("__test.iw") as s:
            block_index = 1
            while True:
                metadata, content = s.read(block_index)
                if not content:
                    break

                reads.append(content)
                block_index += 1

        assert_equals(blocks, reads)
