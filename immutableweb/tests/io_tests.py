#!/usr/bin/env python3
from immutableweb import stream
from immutableweb import crypto
from nose.tools import assert_equals
import unittest

class TestStreamFileIO(unittest.TestCase):

    def test_file_existence(self):
        private_key, public_key = crypto.make_key_pair()
        with open("__test-public.pem", "wb") as f:
            f.write(crypto.get_public_key_pem(public_key))
        with open("__test-private.pem", "wb") as f:
            f.write(crypto.get_private_key_pem(private_key))

        s = stream.Stream()
        s.set_stream_signature_keys("__test-public.pem", "__test-private.pem")
        self.assertRaises(IOError, s.create, "__test.im", { 'foo' : "bar" })


    def test_file_existence_override(self):
        private_key, public_key = crypto.make_key_pair()
        with open("__test-public.pem", "wb") as f:
            f.write(crypto.get_public_key_pem(public_key))
        with open("__test-private.pem", "wb") as f:
            f.write(crypto.get_private_key_pem(private_key))

        s = stream.Stream()
        s.set_stream_signature_keys("__test-public.pem", "__test-private.pem")
        try:
            s.create("__test.im", { 'foo' : "bar" }, force=True)
        except IOError as err:
            self.fail("Force overwrite file dowes not throw the expected exception.")
            return


    def test_missing_file(self):
        s = stream.Stream()
        self.assertRaises(FileNotFoundError, s.open, "__doesnotexist.im")
