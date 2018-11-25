#!/usr/bin/env python3
from immutableweb import stream
from immutableweb import crypto
from nose.tools import assert_equals
import unittest

class TestStreamBlocks(unittest.TestCase):

    def test_block_seek(self):
        private_key, public_key = crypto.make_key_pair()
        with open("__test-public.pem", "wb") as f:
            f.write(crypto.get_public_key_pem(public_key))
        with open("__test-private.pem", "wb") as f:
            f.write(crypto.get_private_key_pem(private_key))

        s = stream.Stream()
        s.set_stream_signature_keys("__test-public.pem", "__test-private.pem")
        s.create("__test.im", { "foo" : "bar" }, force=True)
        s.append(b"1")
        s.append(b"2")
        s.append(b"3")
        s.close()

        s = stream.Stream("__test.im")
        self.assertEqual(s.read(1)[1], b"1")
        self.assertEqual(s.read(2)[1], b"2")
        self.assertEqual(s.read(3)[1], b"3")
        self.assertEqual(s.read(2)[1], b"2")
        self.assertEqual(s.read(3)[1], b"3")
        s.close()


    def test_stream_append_to_existing(self):

        private_key, public_key = crypto.make_key_pair()
        with open("__test-public.pem", "wb") as f:
            f.write(crypto.get_public_key_pem(public_key))
        with open("__test-private.pem", "wb") as f:
            f.write(crypto.get_private_key_pem(private_key))

        s = stream.Stream()
        s.set_stream_signature_keys("__test-public.pem", "__test-private.pem")
        s.create("__test.im", { "foo" : "bar" }, force=True)
        s.append(b"1")
        s.append(b"2")
        s.append(b"3")
        s.close()

        s = stream.Stream("__test.im", append=True)
        try:
            s.verify()
            self.assertEquals(s.state, stream.Stream.STATE_VERIFIED)
        except (stream.InvalidKeyPair, stream.StreamCorrupt, stream.HashFailure, stream.SignatureFailure):
            self.fail("Stream failed to verify")
            return

        s.set_stream_signature_keys("__test-public.pem", "__test-private.pem")
        self.assertEquals(s.state, stream.Stream.STATE_WRITE_VERIFIED)
        s.append(b"4")
        s.close()

        s = stream.Stream("__test.im")
        self.assertEqual(s.verify(), 5)
        s.close()


    def test_stream_append_while_not_at_end(self):

        private_key, public_key = crypto.make_key_pair()
        with open("__test-public.pem", "wb") as f:
            f.write(crypto.get_public_key_pem(public_key))
        with open("__test-private.pem", "wb") as f:
            f.write(crypto.get_private_key_pem(private_key))

        s = stream.Stream()
        s.set_stream_signature_keys("__test-public.pem", "__test-private.pem")
        s.create("__test.im", { "foo" : "bar" }, force=True)
        s.append(b"1")
        s.append(b"2")
        s.read(1)
        s.append(b"3")
        s.close()
