#!/usr/bin/env python3
import os
from nose.tools import assert_equals
import unittest
from tempfile import NamedTemporaryFile
from immutableweb import stream
from immutableweb import crypto

class TestStreamFileIO(unittest.TestCase):

    def setUp(self):
        self.filehandle = NamedTemporaryFile(delete=False)


    def tearDown(self):
        self.filehandle.close()
        try:
            os.unlink(self.filehandle.name)
        except IOError:
            pass


    def test_file_existence(self):
        s = stream.Stream()
        s.set_stream_signature_keys(crypto.make_key_pair())
        self.assertRaises(IOError, s.create, self.filehandle.name)


    def test_file_existence_override(self):

        s = stream.Stream()
        s.set_stream_signature_keys(crypto.make_key_pair())
        try:
            s.create(self.filehandle.name, force=True)
        except IOError as err:
            self.fail("Force overwrite file does not throw the expected exception.")
            return


    def test_missing_file(self):
        s = stream.Stream()
        self.assertRaises(FileNotFoundError, s.open, "__doesnotexist.iw")


    def test_not_iw_stream(self):
        self.filehandle.write(b"\0" * 1024)
        self.filehandle.close()

        s = stream.Stream()
        self.assertRaises(ValueError, s.open, self.filehandle.name)
