#!/usr/bin/env python3
from immutableweb import stream
from immutableweb import crypto
from nose.tools import assert_equals

class TestCreateAndVerifyStream:

    def test_create_and_verify(self):
        private_key, public_key = crypto.make_key_pair()
        with open("__test-public.pem", "wb") as f:
            f.write(crypto.get_public_key_pem(public_key))
        with open("__test-private.pem", "wb") as f:
            f.write(crypto.get_private_key_pem(private_key))

        blocks = [b"random", b"crap"]
        s = stream.Stream()
        s.set_stream_signature_keys("__test-public.pem", "__test-private.pem")
        s.create("__test.im", { 'private-junk' : "this is user junk" }, force=True)
        for b in blocks:
            s.append(content=b)
        s.close()

        reads = []
        with stream.Stream("__test.im") as s:
            block_index = 1
            while True:
                metadata, content = s.read(block_index)
                if not content:
                    break

                reads.append(content)
                block_index += 1

        assert_equals(blocks, reads)
