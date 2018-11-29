#!/usr/bin/env python3
import os
import unittest
from tempfile import NamedTemporaryFile
from nose.tools import assert_equals

from immutableweb import stream
from immutableweb import crypto
from immutableweb import exception as exc

class TestContentEncryption(unittest.TestCase):

    def setUp(self):
        self.filehandle = NamedTemporaryFile(delete=False)


    def tearDown(self):
        self.filehandle.close()
        try:
            os.unlink(self.filehandle.name)
        except IOError:
            pass


    def test_streamwide_content_keys(self):
        public_key, private_key = crypto.make_key_pair()
        public_key2, private_key2 = crypto.make_key_pair()

        s = stream.Stream()
        s.set_stream_signature_keys(public_key, private_key)
        s.set_stream_content_keys(public_key2, private_key2)
        s.create_with_handle(self.filehandle)
        s.append(b"1")
        s.append(b"2")
        s.append(b"3")
        s.close()

        # this time re-open stream without content keys -- content should be returned encrypted
        with stream.Stream(self.filehandle.name) as s:
            s.verify()
            metadata, block = s.read(1) 
            self.assertNotEqual(block, b"1")
            self.assertEqual(crypto.decrypt(private_key2, block), b"1")

        with stream.Stream(self.filehandle.name) as s:
            s.set_stream_content_keys(public_key2, private_key2)
            s.verify()
            _, block = s.read(1) 
            print(block)
            self.assertEqual(block, b"1")


    def test_block_content_keys(self):
        s = stream.Stream()
        public_key, private_key = crypto.make_key_pair()
        public_key2, private_key2 = crypto.make_key_pair()
        s.set_stream_signature_keys(public_key, private_key)
        s.create_with_handle(self.filehandle)
        s.append(b"1")
        s.append(b"2", public_key=public_key2)
        s.append(b"3")
        s.close()

        with stream.Stream(self.filehandle.name) as s:
            s.verify()
            metadata, block = s.read(2, private_key=private_key2) 
            self.assertEqual(block, b"2")
            metadata, block = s.read(3) 
            self.assertEqual(block, b"3")
