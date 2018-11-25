#!/usr/bin/env python3
from nose.tools import assert_equals
import unittest

from immutableweb import stream
from immutableweb import crypto
from immutableweb import exception as exc

class TestContentEncryption(unittest.TestCase):


    def test_streamwide_content_keys(self):
        private_key, public_key = crypto.make_key_pair()
        with open("__test-public.pem", "wb") as f:
            f.write(crypto.get_public_key_pem(public_key))
        with open("__test-private.pem", "wb") as f:
            f.write(crypto.get_private_key_pem(private_key))

        private_key2, public_key2 = crypto.make_key_pair()
        with open("__test2-public.pem", "wb") as f:
            f.write(crypto.get_public_key_pem(public_key2))
        with open("__test2-private.pem", "wb") as f:
            f.write(crypto.get_private_key_pem(private_key2))

        s = stream.Stream()
        s.set_stream_signature_keys("__test-public.pem", "__test-private.pem")
        s.set_stream_content_keys("__test2-public.pem", "__test2-private.pem")
        # TODO: add metadata tests
        s.create("__test.im", { "foo" : "bar" }, force=True)
        s.append(b"1")
        s.append(b"2")
        s.append(b"3")
        s.close()

        # this time re-open stream without content keys -- content should be returned encrypted
        with stream.Stream("__test.im") as s:
            s.verify()
            metadata, block = s.read_block(1) 
            self.assertNotEqual(block, b"1")
            self.assertEqual(crypto.decrypt(private_key2, block), b"1")

        with stream.Stream("__test.im") as s:
            s.set_stream_content_keys("__test2-public.pem", "__test2-private.pem")
            s.verify()
            _, block = s.read_block(1) 
            print(block)
            self.assertEqual(block, b"1")
