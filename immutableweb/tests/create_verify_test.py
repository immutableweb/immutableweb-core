#!/usr/bin/env python3
import os
from nose.tools import assert_equals
from tempfile import NamedTemporaryFile

from immutableweb import stream
from immutableweb import crypto

class TestCreateAndVerifyStream:

    def setUp(self):
        self.filehandle = NamedTemporaryFile(delete=False)


    def tearDown(self):
        self.filehandle.close()
        try:
            os.unlink(self.filehandle.name)
        except IOError:
            pass

    def test_create_and_verify(self):
        blocks = [b"random", b"crap"]
        s = stream.Stream()
        s.set_stream_signature_keys(crypto.make_key_pair())
        s.create_with_handle(self.filehandle)
        for b in blocks:
            s.append(content=b)
        s.close()

        reads = []
        with stream.Stream(self.filehandle.name) as s:
            block_index = 1
            while True:
                metadata, content = s.read(block_index)
                if not content:
                    break

                reads.append(content)
                block_index += 1

        assert_equals(blocks, reads)
