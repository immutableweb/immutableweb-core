import sys
import os
import struct
from hashlib import sha256
import ujson
import base64

from immutableweb import crypto
from immutableweb import exception as exc

MANIFEST_METADATA_STREAM_SIGNATURE_PUBLIC_KEY = "_stream_signature-public_key"

class Stream(object):

    UINT32_SIZE    = 4  # For metadata, signature sizes
    UINT64_SIZE    = 8  # For content size
    HASH_SIZE      = 32 # For sha256
    MAX_BLOCK_SIZE = 4294967295 # (2 ^ 32) - 1
    MANIFEST_BLOCK = 0

    # These are the various states that this object can be in with regard to the stream:
    # The stream has not been verified.
    STATE_UNVERIFIED     = 0
    # The stream has been verified.
    STATE_VERIFIED       = 1
    # The stream has been verified for writing (a valid private key has ben provided)
    STATE_WRITE_VERIFIED = 2
    # The stream is corrupt and should not be trusted.
    STATE_CORRUPTED      = 3

    def __init__(self, filename = None, append = False):
        self.stream_signature_key_public = None
        self.stream_signature_key_private = None
        self.stream_content_key_public = None
        self.stream_content_key_private = None

        # Current state of the stream object
        self.current_state = self.STATE_UNVERIFIED

        # Keep track of the current block ready to read, or -1 if not set.
        self.current_block = -1

        # Keep track of the current block position ready to read, or -1 if not set.
        self.current_block_pos = -1

        # keep track of the last block's hash value
        self.last_block_hash = None

        if filename:
            self.open(filename, append)


    def __enter__(self):
        return self


    def __exit__(self, type, value, traceback):
        self.close()


    @property
    def state(self):
        return self.current_state


    def set_stream_signature_keys(self, public_key_filename, private_key_filename = None):
        '''
            Set the public key for verifying data in the stream. Optionally, 
            set the private key for appending new data to the stream. Only needed if
            you intend to append more blocks. At minimum, a public key for verifying
            the stream is required.
        '''

        if public_key_filename:
            public_key = crypto.load_public_key(public_key_filename)
        else:
            public_key = None

        if private_key_filename:
            private_key = crypto.load_private_key(private_key_filename)
        else:
            private_key = None

        if self.stream_signature_key_public and \
           crypto.serialize_public_key(public_key) != crypto.serialize_public_key(self.stream_signature_key_public):
            raise exc.InvalidKeyPair

        if public_key and private_key:
            crypto.validate_key_pair(private_key, public_key)
            if self.current_state == self.STATE_VERIFIED:
                self.current_state = self.STATE_WRITE_VERIFIED

        self.stream_signature_key_public = public_key
        self.stream_signature_key_private = private_key


    # TODO: Implement stream wide keys
    def set_stream_content_keys(self, public_key_filename, private_key_filename = None):
        ''' 
            Set the encyption keys to be used by the whole stream. If the caller plans to 
            append to the stream, a private key needs to be provided as well. If no keys are
            provided by this function, the data blocks will not be encrypted, unless encryption
            keys are provided on a per-block basis. Per block basis encrption keys override
            stream level encryption keys.
        '''
        if public_key_filename:
            public_key = crypto.load_public_key(public_key_filename)
        else:
            public_key = None

        if private_key_filename:
            private_key = crypto.load_private_key(private_key_filename)
        else:
            private_key = None

        if crypto.serialize_public_key() != crypto.serialize_public_key(self.stream_signature_public_key):
            raise exc.InvalidKeyPair("Public key does not match key found in stream.")

        if public_key and private_key:
            crypto.validate_key_pair(self.stream_signature_key_private, self.stream_signature_key_public)

        self.stream_content_key_public = public_key
        self.stream_content_key_private = private_key


    def _seek_to_beginning(self):
        '''
            Reset the current block index/position to he beginning
        '''
        self.current_block = self.current_block_pos = 0
        self.fhandle.seek(0)
        self.last_block_hash = None


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


    def _seek_to_block(self, index):
        if self.current_block < 0 or index < self.current_block:
            self._seek_to_beginning()

        while self._seek_to_next_block():
            if self.current_block == index:
                return


    def _validate_and_parse_block(self, block):

        offset = 0

        prev_block_hash = block[offset:offset + self.HASH_SIZE]
        offset += self.HASH_SIZE

        metadata_len = struct.unpack("<L", block[offset:offset+self.UINT32_SIZE])[0]
        offset += self.UINT32_SIZE
        metadata = block[offset:offset + metadata_len]
        offset += metadata_len

        metadata = ujson.loads(metadata)

        content_len = struct.unpack("<Q", block[offset:offset+self.UINT64_SIZE])[0]
        offset += self.UINT64_SIZE

        content = block[offset:offset + content_len]
        offset += content_len

        hash = block[offset:offset + self.HASH_SIZE]
        offset += self.HASH_SIZE

        signature_len = struct.unpack("<L", block[offset:offset+self.UINT32_SIZE])[0]
        offset += self.UINT32_SIZE

        signature = block[offset:offset + signature_len]
        offset += signature_len

        sha = sha256()
        sha.update(block[:(len(block) -  self.HASH_SIZE - self.UINT32_SIZE - signature_len)])
        digest = sha.digest()

        if digest != hash:
            raise exc.BlockHashVerifyFailureException

        if self.current_block == 0:
            self.stream_signature_key_public = crypto.deserialize_public_key( \
                bytes(metadata[MANIFEST_METADATA_STREAM_SIGNATURE_PUBLIC_KEY], "utf-8"))

        try:
            crypto.verify(self.stream_signature_key_public, block[:(len(block) - self.UINT32_SIZE - signature_len)], signature)
        except exc.BlockSignatureVerifyFailureException:
            self.current_state = self.STATE_CORRUPTED
            raise

        return (metadata, content, sha)
  

    def create_with_handle(self, fhandle, manifest_metadata):
        '''
            Open a new stream, based on the file-like handle. The stream must be empty.
        '''

        if not manifest_metadata:
            raise ValueError("Missing manifest_metadata")

        self.fhandle = fhandle
        self.fhandle.seek(0, 2)
        if self.fhandle.tell() != 0:
            raise ValueError("Stream file not empty.")

        if not self.stream_signature_key_public: 
            raise exc.MissingKey("Public stream key is missing.")

        if not self.stream_signature_key_private: 
            raise exc.MissingKey("Private stream key is missing.")

        manifest_metadata[MANIFEST_METADATA_STREAM_SIGNATURE_PUBLIC_KEY] = crypto.serialize_public_key(self.stream_signature_key_public) 
        self.last_block_hash = sha256()

        self.current_state = self.STATE_WRITE_VERIFIED
        self.append(bytes(), metadata=manifest_metadata)


    def create(self, filename, manifest_metadata, force=False):
        '''
            Open a new file based stream. The stream must not exist. Most of the 
            opening work is actually done by open_with_handle()
        '''

        if not force and os.path.exists(filename):
            raise IOError("File exists")

        self.create_with_handle(open(filename, "wb"), manifest_metadata)


    def open(self, filename, append = False):
        '''
            Open a stream using a filename
        '''

        if append:
            fhandle = open(filename, "a+b")
        else:
            fhandle = open(filename, "rb")

        return self.open_with_handle(fhandle)


    def open_with_handle(self, fhandle):
        ''' 
            Open a file given a file-like object
        '''

        self.fhandle = fhandle
        self._seek_to_beginning()
        self.current_state = self.STATE_UNVERIFIED
        (metadata, _) = self.read_block(0)


    def close(self, close_handle=True):
        '''
            Close the stream, flushing bits as necessary. Close the associated file if close_file is True.
        '''
        if close_handle:
            self.fhandle.close()
        else:
            self.fhandle.flush()

        self.fhandle = None
        self.stream_signature_key_public = None
        self.stream_signature_key_private = None
        self.stream_content_key_public = None
        self.stream_content_key_private = None
        self.current_state = self.STATE_UNVERIFIED
        self.current_block = -1
        self.current_block_pos = -1
        self.last_block_hash = None


    def verify(self):

        public_key = None

        self._seek_to_beginning()
        self.current_state = self.STATE_UNVERIFIED
        while True:
            (metadata, content) = self.read_block(self.current_block)
            if not content and not metadata:
                break

            if self.current_block == 1:
                public_key = metadata[MANIFEST_METADATA_STREAM_SIGNATURE_PUBLIC_KEY]

        self.current_state = self.STATE_VERIFIED

        if public_key and public_key == crypto.serialize_public_key(self.stream_signature_key_public):
            if self.stream_signature_key_private:
                self.current_state = self.STATE_WRITE_VERIFIED


    def read_block(self, index):
        '''
            Read and return the requested block. 
        '''

        if self.current_state == self.STATE_CORRUPTED:
            raise ExceptionCorruptStream("Stream corrupted, refusing to read.")

        if self.current_block >= 0 and self.current_block != index:
            self._seek_to_block(index)

        try:
            block_size_raw = self.fhandle.read(self.UINT64_SIZE)
        except IOError as err:
            self.current_state = STATE_CORRUPTED
            raise ExceptionCorruptStream(err)

        num_read = len(block_size_raw)
        if num_read == 0:
            return (None, None)

        if num_read < self.UINT64_SIZE:
            self.current_state = self.STATE_CORRUPTED
            raise ExceptionCorruptStream

        try:
            block_size = struct.unpack("<Q", block_size_raw)[0]
            if block_size < self.UINT64_SIZE + 1 or block_size > self.MAX_BLOCK_SIZE:
                self.current_state = self.STATE_CORRUPTED
                raise ExceptionCorruptStream

            block = self.fhandle.read(block_size - self.UINT64_SIZE);
        except IOError:
            self.current_state = self.STATE_CORRUPTED
            raise ExceptionCorruptStream
            
        metadata, content, hash = self._validate_and_parse_block(block)

        self.current_block = index + 1
        self.current_block_pos = self.fhandle.tell()
        self.last_block_hash = hash

        return (metadata, content)


    def append(self, content = None, metadata = None, public_key=None, private_key=None):
        '''
            Append the block to this stream.
        '''

        if self.current_state != self.STATE_WRITE_VERIFIED:
            raise exc.InvalidState("Stream not in verified for write state, cannot append.") 

        if not self.stream_signature_key_private:
            raise exc.MissingKey("Private stream key not set.")

        if not self.stream_signature_key_public:
            raise exc.MissingKey("Public stream key not set.")

        if type(content) is not bytes:
            raise ValueError("content must be type bytes.")

        if self.current_block < 0 and not metadata:
            raise ValueError("Metadata for block 0 (aka the manifest block) must be given.")

        metadata = bytes(ujson.dumps(metadata), 'utf-8')
        metadata_len = len(metadata)
        content_len = len(content) 

        sha = sha256()

        if self.last_block_hash:
            last_hash = self.last_block_hash
        else:
            raise exc.InvalidState("last block hash not set, stream not valid.")

        block_data = bytes(last_hash.digest())
        block_data += struct.pack("<L", metadata_len)
        block_data += metadata
        block_data += struct.pack("<Q", content_len)
        block_data += content

        sha.update(block_data)
        digest = sha.digest()
        block_data += digest

        self.last_block_hash = sha
        self.current_block += 1

        signature = crypto.sign(self.stream_signature_key_private, block_data)
        block_data += struct.pack("<L", len(signature))
        block_data += signature
        block_len = self.UINT64_SIZE + len(block_data)

        self.fhandle.seek(0, 2)
        self.fhandle.write(struct.pack("<Q", block_len))
        self.fhandle.write(block_data)

        return sha 
