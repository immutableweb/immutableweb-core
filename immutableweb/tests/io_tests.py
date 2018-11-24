#!/usr/bin/env python3
from immutableweb import stream
from immutableweb import key
from nose.tools import assert_equals
import unittest

class TestStreamFileIO(unittest.TestCase):

    def test_file_existence(cls):
        private_key, public_key = key.make_key_pair()
        with open("__test-public.pem", "wb") as f:
            f.write(key.get_public_key_pem(public_key))
        with open("__test-private.pem", "wb") as f:
            f.write(key.get_private_key_pem(private_key))

        s = stream.Stream()
        s.set_stream_signature_keys("__test-public.pem", "__test-private.pem")
        cls.assertRaises(IOError, s.create, "__test.im", { 'foo' : "bar" })


    def test_file_existence_override(cls):
        private_key, public_key = key.make_key_pair()
        with open("__test-public.pem", "wb") as f:
            f.write(key.get_public_key_pem(public_key))
        with open("__test-private.pem", "wb") as f:
            f.write(key.get_private_key_pem(private_key))

        s = stream.Stream()
        s.set_stream_signature_keys("__test-public.pem", "__test-private.pem")
        try:
            s.create("__test.im", { 'foo' : "bar" }, force=True)
        except IOError as err:
            cls.fail("Force overwrite file dowes not throw the expected exception.")
            return


    def test_missing_file(cls):
        s = stream.Stream()
        cls.assertRaises(FileNotFoundError, s.open, "__doesnotexist.im")
