#!/usr/bin/env python3
from immutableweb import stream
from immutableweb import crypto
from nose.tools import assert_equals
import unittest

class TestStreamFileIO(unittest.TestCase):

    def test_file_existence(self):
        s = stream.Stream()
        s.set_stream_signature_keys(crypto.make_key_pair())
        self.assertRaises(IOError, s.create, "__test.iw")


    def test_file_existence_override(self):

        s = stream.Stream()
        s.set_stream_signature_keys(crypto.make_key_pair())
        try:
            s.create("__test.iw", force=True)
        except IOError as err:
            self.fail("Force overwrite file dowes not throw the expected exception.")
            return


    def test_missing_file(self):
        s = stream.Stream()
        self.assertRaises(FileNotFoundError, s.open, "__doesnotexist.iw")


    def test_not_iw_stream(self):
        with open("not-iw.iw", "wb") as f:
            f.write(b"\0" * 1024)

        s = stream.Stream()
        self.assertRaises(ValueError, s.open, "not-iw.iw")
