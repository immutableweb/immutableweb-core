import os
import sys
import struct
from hashlib import sha256
import gnupg
import ujson
import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

class ExceptionMissingStreamSignatureKey(Exception):
    pass

class ExceptionNoPrivateSignatureKey(Exception):
    pass

class ExceptionMissingContentKey(Exception):
    pass

class ExceptionMissingManifestBlock(Exception):
    pass

class ExceptionFileNotEmpty(Exception):
    pass

class ExceptionCorruptStream(Exception):
    pass

class ExceptionWriteError(Exception):
    pass

class BlockHashVerifyFailureException(Exception):
    pass

class BlockSignatureVerifyFailureException(Exception):
    pass

class Stream(object):

    UINT32_SIZE    = 4  # For metadata, signature sizes
    UINT64_SIZE    = 8  # For content size
    HASH_SIZE      = 32 # For sha256
    MAX_BLOCK_SIZE = 4294967295 # (2 ^ 32) - 1
    MANIFEST_BLOCK = 0

    def __init__(self):
        self.stream_signature_key_public = None
        self.stream_signature_key_private = None
        self.stream_content_key_public = None
        self.stream_content_key_private = None

        # Keep track of the current block ready to read, or -1 if not set.
        self.current_block = -1

        # Keep track of the current block position ready to read, or -1 if not set.
        self.current_block_pos = -1


    def _load_private_key(self, filename):
        with open(filename, "rb") as key_file:
             private_key = serialization.load_pem_private_key(
                 key_file.read(),
                 password=None,
                 backend=default_backend())
        return private_key


    def _load_public_key(self, filename):
        with open(filename, "rb") as key_file:
             public_key = serialization.load_pem_public_key(
                 key_file.read(),
                 backend=default_backend())
        return public_key


    def _serialize_public_key(self, key):
        pem = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

        return pem.decode('utf-8')


    def set_stream_signature_keys(self, public_key_filename, private_key_filename = None):
        '''
            Set the public key for verifying data in the stream. Optionally, 
            set the private key for appending new data to the stream. Only needed if
            you intend to append more blocks. At minimum, a public key for verifying
            the stream is required.
        '''
        if public_key_filename:
            self.stream_signature_key_public = self._load_public_key(public_key_filename)
        if private_key_filename:
            self.stream_signature_key_private = self._load_private_key(private_key_filename)


    def set_stream_content_keys(self, public_key_filename, private_key_filename = None):
        ''' 
            Set the encyption keys to be used by the whole stream. If the caller plans to 
            append to the stream, a private key needs to be provided as well. If no keys are
            provided by this function, the data blocks will not be encrypted, unless encryption
            keys are provided on a per-block basis. Per block basis encrption keys override
            stream level encryption keys.
        '''
        if public_key_filename:
            self.stream_contet_key_public = self._load_public_key(stream_signature_key_public_filename)
        if private_key_filename:
            self.stream_content_key_private = self._load_private_key(stream_signature_key_private_filename)


    def __create(self, fhandle, manifest_block):
        '''
            Open a new stream, based on the file-like handle. The stream must be empty.
        '''
        pass


    def create(self, filename, manifest_block):
        '''
            Open a new file based stream. The stream file must not exist.
        '''

        if os.path.exists(filename):
            raise IOError("File exists")

        if not manifest_block:
            raise ExceptionMissingManifestBlock

        manifest_block["_stream_signature-public_key"] = self._serialize_public_key(self.stream_signature_key_public) 

        self.fhandle = open(filename, "wb")
        self.append(0, metadata=manifest_block, content=bytes())


    def open(self, filename):
        '''
            Open a stream using a filename
        '''

        self.fhandle = open(filename, "rb")
        if not self.stream_signature_key_public:
            raise ExceptionMissingStreamSignatureKey

        self.current_block = self.current_block_pos = -1
        self.manifest_block = self.read_block(0)


    def _open(self, fhandle):
        ''' 
            Open a file given a file-like object
        '''

        if not self.stream_signature_key_public:
            raise ExceptionMissingStreamSignatureKey

        self.current_block = self.current_block_pos = -1 
        self.manifest_block = self.read_block(0)


    def close(self, close_handle=True):
        '''
            Close the stream, flushing bits as necessary. Close the associated file if close_file is True.
        '''
        if close_handle:
            self.fhandle.close()
        else:
            self.fhandle.flush()

        self.fhandle = None


    def _seek_to_beginning(self):
        '''
            Reset the current block index/position to he beginning
        '''
        self.current_block = self.current_block_pos = 0
        self.fhandle.seek(0)


    def _seek_to_next_block(self):
        try:
            block_size = struct.unpack("<Q", self.fhandle.read(self.UINT64_SIZE))[0]
            if block_size < self.UINT64_SIZE + 1 or block_size > self.MAX_BLOCK_SIZE:
                raise ExceptionCorruptStream

            self.fhandle.seek(block_size - self.UINT64_SIZE, 1)
        except IOError:
            self.current_block = self.current_block_pos = -1
            return 0

        self.current_block_pos = self.fhandle.tell()
        self.current_block += 1

        return block_size

    def _validate_and_parse_block(self, block):

        offset = 0

        prev_block_hash = block[offset:offset + self.HASH_SIZE]
        offset += self.HASH_SIZE

        metadata_len = struct.unpack("<L", block[offset:offset+self.UINT32_SIZE])[0]
        print("metadata len %d" % metadata_len)
        offset += self.UINT32_SIZE
        metadata = block[offset:offset + metadata_len]
        print(metadata)
        offset += metadata_len

        content_len = struct.unpack("<Q", block[offset:offset+self.UINT64_SIZE])[0]
        print("content len: %d" % content_len)
        offset += self.UINT64_SIZE
        print(offset)

        content = block[offset:offset + content_len]
        offset += content_len
        print(offset)

        hash = block[offset:offset + self.HASH_SIZE]
        offset += self.HASH_SIZE
        print(offset)

        signature_len = struct.unpack("<L", block[offset:offset+self.UINT32_SIZE])[0]
        print("sig len: %d" % signature_len)
        offset += self.UINT32_SIZE
        print(offset)

        signature = block[offset:offset + signature_len]
        offset += signature_len
        print(offset)

        sha = sha256()
        sha.update(block[:(len(block) -  self.HASH_SIZE - self.UINT32_SIZE - signature_len)])
        digest = sha.digest()

        with open("/tmp/read.bin", "wb") as f:
            f.write(block[:(len(block) -  self.HASH_SIZE - self.UINT32_SIZE - signature_len)])

        print("digest: ", digest)
        print("hash: ", hash)
        if digest != hash:
            raise BlockHashVerifyFailureException

        self._verify_block(block[:(len(block) - signature_len)], signature)
   

    def read_block(self, index):
        '''
            Read and return the requested block. 
        '''

        if self.current_block >= 0 and self.current_block != index:
            self._seek_to_block(index)

        try:
            block_size_raw = self.fhandle.read(self.UINT64_SIZE)
        except IOError as err:
            raise ExceptionCorruptStream(err)

        num_read = len(block_size_raw)
        if num_read == 0:
            return None

        if num_read < self.UINT64_SIZE:
            raise ExceptionCorruptStream

        try:
            block_size = struct.unpack("<Q", block_size_raw)[0]
            print("block size raw: %d" % block_size)
            if block_size < self.UINT64_SIZE + 1 or block_size > self.MAX_BLOCK_SIZE:
                raise ExceptionCorruptStream

            block = self.fhandle.read(block_size - self.UINT64_SIZE);
        except IOError:
            raise ExceptionCorruptStream
            
        self.current_block = index + 1
        self.current_block_pos = self.fhandle.tell()

        return self._validate_and_parse_block(block)


    def _sign_block(self, block):
        signature = self.stream_signature_key_private.sign(
            block,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256())

        return signature


    def _verify_block(self, block, signature):
        try:
            signature = self.stream_signature_key_public.verify(
                signature,
                block,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256())
        except InvalidSignature:
            raise BlockSignatureVerifyFailureException


    def _serialize_signature(self, signature):
        return base64.b64encode(signature, altchars=None)
       

    def _parse_signature(self, signature):
        return base64.b64decode(signature)
       

    def append(self, prev_block_hash, content = None, metadata = None, 
               public_key=None, private_key=None):
        '''
            Append the block to this stream.
        '''

        if not self.stream_signature_key_private:
            raise(ExceptionNoPrivateSignatureKey)

        if (public_key or private_key) and (not private_key or not public_key):
            raise(ExceptionMissingContentKey)

        if type(content) is not bytes:
            raise ValueError("content must be type bytes.")

        metadata = bytes(ujson.dumps(metadata), 'utf-8')
        metadata_len = len(metadata)
        content_len = len(content) 

        print("metadata len: %d" % metadata_len)
        print("content len: %d" % content_len)

        sha = sha256()

        if prev_block_hash:
            block_data = bytes(prev_block_hash.digest())
        else:
            print("got no hash")
            block_data = bytes(b'\0' * self.HASH_SIZE)

        block_data += struct.pack("<L", metadata_len)
        block_data += metadata
        block_data += struct.pack("<Q", content_len)
        block_data += content

        with open("/tmp/write.bin", "wb") as f:
            f.write(block_data)

        sha.update(block_data)
        digest = sha.digest()
        block_data += digest
        signature = self._sign_block(block_data)
        block_data += struct.pack("<L", len(signature))
        block_data += signature
        block_len = self.UINT64_SIZE + len(block_data)

        try:
            self.fhandle.seek(0, 2)
            self.fhandle.write(struct.pack("<Q", block_len))
            self.fhandle.write(block_data)
        except IOError as err:
            raise ExceptionWriteError(err)

        return sha 
