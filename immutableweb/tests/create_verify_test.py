#!/usr/bin/env python3
import key
import stream
from nose.tools import assert_equals

class TestCreateAndVerifyStream:

    def test_create_and_verify(cls):
        private_key, public_key = key.make_key_pair()
        with open("__test-public.pem", "wb") as f:
            f.write(key.get_public_key_pem(public_key))
        with open("__test-private.pem", "wb") as f:
            f.write(key.get_private_key_pem(private_key))

        blocks = [b"random", b"crap"]
        s = stream.Stream()
        s.set_stream_signature_keys("__test-public.pem", "__test-private.pem")
        s.create("__test.im", { 'private-junk' : "this is user junk" }, force=True)
        for b in blocks:
            s.append(content=b)
        s.close()

        read_blocks = []
        with stream.Stream("__test.im") as s:
            block_index = 1
            while True:
                metadata, content = s.read_block(block_index)
                if not content:
                    break

                read_blocks.append(content)
                block_index += 1

        assert_equals(blocks, read_blocks)
