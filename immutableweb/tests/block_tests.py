#!/usr/bin/env python3
from immutableweb import stream
from immutableweb import key
from nose.tools import assert_equals
import unittest

class TestStreamBlocks(unittest.TestCase):

    def test_block_seek(cls):
        private_key, public_key = key.make_key_pair()
        with open("__test-public.pem", "wb") as f:
            f.write(key.get_public_key_pem(public_key))
        with open("__test-private.pem", "wb") as f:
            f.write(key.get_private_key_pem(private_key))

        s = stream.Stream()
        s.set_stream_signature_keys("__test-public.pem", "__test-private.pem")
        s.create("__test.im", { "foo" : "bar" }, force=True)
        s.append(b"1")
        s.append(b"2")
        s.append(b"3")
        s.close()

        s = stream.Stream("__test.im")
        cls.assertEqual(s.read_block(1)[1], b"1")
        cls.assertEqual(s.read_block(2)[1], b"2")
        cls.assertEqual(s.read_block(3)[1], b"3")
        cls.assertEqual(s.read_block(2)[1], b"2")
        cls.assertEqual(s.read_block(3)[1], b"3")
        s.close()
