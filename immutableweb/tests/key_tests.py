#!/usr/bin/env python3
import os
import unittest
from tempfile import NamedTemporaryFile, TemporaryDirectory
from nose.tools import assert_equals

from immutableweb import stream
from immutableweb import crypto
from immutableweb import exception as exc

class TestKeys(unittest.TestCase):

    def setUp(self):
        self.filehandle = NamedTemporaryFile(delete=False)


    def tearDown(self):
        self.filehandle.close()
        try:
            os.unlink(self.filehandle.name)
        except IOError:
            pass


    def test_missing_keys(self):
        s = stream.Stream()
        self.assertRaises(exc.MissingKey, s.create_with_handle, self.filehandle)


    def test_mismatched_keys(self):
        s = stream.Stream()
        public_key, private_key = crypto.make_key_pair()
        public_key2, private_key2 = crypto.make_key_pair()
        self.assertRaises(exc.InvalidKeyPair, s.set_stream_signature_keys, public_key2, private_key)


    def test_missing_key_files(self):
        s = stream.Stream()
        self.assertRaises(FileNotFoundError, s.set_stream_signature_keys_filename, "<doesnotexist>", "<neither does this>")


    def test_set_key_signature_key(self):

        s = stream.Stream()
        public_key, private_key = crypto.make_key_pair()
        public_key2, private_key2 = crypto.make_key_pair()
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

        self.assertRaises(exc.InvalidKeyPair, s.set_stream_signature_keys, public_key2, private_key2)
        s.close()


    def test_file_keys(self):

        with TemporaryDirectory() as tmpdirname:
            public_key, private_key = crypto.make_key_pair()
            with open(os.path.join(tmpdirname,"__test-public.pem"), "wb") as f:
                f.write(crypto.get_public_key_pem(public_key))
            with open(os.path.join(tmpdirname,"__test-private.pem"), "wb") as f:
                f.write(crypto.get_private_key_pem(private_key))

            s = stream.Stream()
            s.set_stream_signature_keys_filename(os.path.join(tmpdirname, "__test-public.pem"), 
                os.path.join(tmpdirname, "__test-private.pem"))


    def test_file_content_keys(self):

        with TemporaryDirectory() as tmpdirname:
            public_key, private_key = crypto.make_key_pair()
            with open(os.path.join(tmpdirname, "__test-public.pem"), "wb") as f:
                f.write(crypto.get_public_key_pem(public_key))
            with open(os.path.join(tmpdirname, "__test-private.pem"), "wb") as f:
                f.write(crypto.get_private_key_pem(private_key))

            s = stream.Stream()
            s.set_stream_content_keys_filename(os.path.join(tmpdirname, "__test-public.pem"), 
                os.path.join(tmpdirname, "__test-private.pem"))


    def test_metadata(self):

        metadata = { 'foo' : 'bar' }
        metadata2 = { 'foo' : 'bar' }

        s = stream.Stream()
        s.set_stream_signature_keys(crypto.make_key_pair())
        s.create_with_handle(self.filehandle)
        s.append(b"1")
        s.append(b"2", metadata2)
        s.append(b"3")
        s.close()

        s = stream.Stream(self.filehandle.name, append=True)
        s.verify()
        (read_metadata, content) = s.read(0)
        if stream.MANIFEST_METADATA_STREAM_SIGNATURE_PUBLIC_KEY not in read_metadata:
            self.fail("Stream signature public key not found in manifest data.")

        (read_metadata, content) = s.read(2)
        self.assertEqual(read_metadata, metadata2)
        s.close()


    def test_stream_id(self):

        s = stream.Stream()
        self.assertEqual(s.uuid, "")
        s.set_stream_signature_keys(crypto.make_key_pair())
        s.create_with_handle(self.filehandle)
        self.assertEqual(len(s.uuid), 32)
        s.close()

        s = stream.Stream(self.filehandle.name)
        s.verify()
        self.assertEqual(len(s.uuid), 32)
        s.close()
