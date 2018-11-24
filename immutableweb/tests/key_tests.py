#!/usr/bin/env python3
from immutableweb import stream
from immutableweb import key
from nose.tools import assert_equals
import unittest

class TestKeys(unittest.TestCase):

    def test_missing_keys(self):
        s = stream.Stream()
        self.assertRaises(stream.MissingKey, s.create, "__test.im", { 'foo' : 'bar' }, force=True)


    def test_mismatched_keys(self):
        private_key, public_key = key.make_key_pair()
        with open("__test-public.pem", "wb") as f:
            f.write(key.get_public_key_pem(public_key))
        with open("__test-private.pem", "wb") as f:
            f.write(key.get_private_key_pem(private_key))

        private_key2, public_key2 = key.make_key_pair()
        with open("__test2-public.pem", "wb") as f:
            f.write(key.get_public_key_pem(public_key2))
        with open("__test2-private.pem", "wb") as f:
            f.write(key.get_private_key_pem(private_key2))

        s = stream.Stream()
        self.assertRaises(stream.InvalidKeyPair, s.set_stream_signature_keys, "__test-public.pem", "__test2-private.pem")


    def test_missing_key_files(self):
        s = stream.Stream()
        self.assertRaises(FileNotFoundError, s.set_stream_signature_keys, "<doesnotexist>", "<neither does this>")


    def test_set_key_signature_key(self):

        private_key, public_key = key.make_key_pair()
        with open("__test-public.pem", "wb") as f:
            f.write(key.get_public_key_pem(public_key))
        with open("__test-private.pem", "wb") as f:
            f.write(key.get_private_key_pem(private_key))

        private_key2, public_key2 = key.make_key_pair()
        with open("__test2-public.pem", "wb") as f:
            f.write(key.get_public_key_pem(public_key2))
        with open("__test2-private.pem", "wb") as f:
            f.write(key.get_private_key_pem(private_key2))

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
        except (stream.InvalidKeyPair, stream.ExceptionCorruptStream, stream.BlockHashVerifyFailureException, stream.BlockSignatureVerifyFailureException):
            self.fail("Stream failed to verify")
            return

        self.assertRaises(stream.InvalidKeyPair, s.set_stream_signature_keys, "__test2-public.pem", "__test2-private.pem")
        s.close()
