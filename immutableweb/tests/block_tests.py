#!/usr/bin/env python3
import unittest
import os
from tempfile import NamedTemporaryFile
from nose.tools import assert_equals

from immutableweb import stream
from immutableweb import crypto

class TestStreamBlocks(unittest.TestCase):

    def setUp(self):
        self.filehandle = NamedTemporaryFile(delete=False)


    def tearDown(self):
        self.filehandle.close()
        try:
            os.unlink(self.filehandle.name)
        except IOError:
            pass


    def test_block_seek(self):
        s = stream.Stream()
        s.set_stream_signature_keys(crypto.make_key_pair())
        s.create_with_handle(self.filehandle)
        s.append(b"1")
        s.append(b"2")
        s.append(b"3")
        s.close()

        s = stream.Stream(self.filehandle.name)
        self.assertEqual(s.read(1)[1], b"1")
        self.assertEqual(s.read(2)[1], b"2")
        self.assertEqual(s.read(3)[1], b"3")
        self.assertEqual(s.read(2)[1], b"2")
        self.assertEqual(s.read(3)[1], b"3")
        s.close()


    def test_stream_append_to_existing(self):
        s = stream.Stream()
        public_key, private_key = crypto.make_key_pair()
        s.set_stream_signature_keys(public_key, private_key)
        s.create_with_handle(self.filehandle)
        s.append(b"1")
        s.append(b"2")
        s.append(b"3")
        s.close()

        s = stream.Stream(self.filehandle.name, append=True)
        try:
            s.verify()
            self.assertEquals(s.state, stream.Stream.STATE_VERIFIED)
        except (stream.InvalidKeyPair, stream.StreamCorrupt, stream.HashFailure, stream.SignatureFailure):
            self.fail("Stream failed to verify")
            return

        s.set_stream_signature_keys(public_key, private_key)
        self.assertEquals(s.state, stream.Stream.STATE_WRITE_VERIFIED)
        s.append(b"4")
        s.close()

        s = stream.Stream(self.filehandle.name)
        self.assertEqual(s.verify(), 5)
        s.close()


    def test_stream_append_while_not_at_end(self):

        s = stream.Stream()
        s.set_stream_signature_keys(crypto.make_key_pair())
        s.create_with_handle(self.filehandle)
        s.append(b"1")
        s.append(b"2")
        s.read(1)
        s.append(b"3")
        s.close()
