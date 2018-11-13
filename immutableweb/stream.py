import os
import sys
import struct
import ujson

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

class Stream(object):

    BLOCK_SIZE_BYTES = 8
    MAX_BLOCK_SIZE = 4294967295 # (2 ^ 32) - 1
    MANIFEST_BLOCK = 0

    def __init__(self, stream_signature_key_public):
        self.stream_signature_key_public = stream_signature_key_public
        self.stream_signature_key_private = None
        self.stream_content_key_public = None
        self.stream_content_key_private = None

        # Keep track of the current block ready to read, or -1 if not set.
        self.current_block = -1

        # Keep track of the current block position ready to read, or -1 if not set.
        self.current_block_pos = -1


    def set_stream_signature_keys(self, public_key, private_key = None):
        '''
            Set the public key for verifying data in the stream. Optionally, 
            set the private key for appending new data to the stream. Only needed if
            you intend to append more blocks. At minimum, a public key for verifying
            the stream is required.
        '''
        self.stream_signature_key_public = public_key
        self.stream_signature_key_private = private_key


    def set_stream_content_keys(self, public_key, private_key = None):
        ''' 
            Set the encyption keys to be used by the whole stream. If the caller plans to 
            append to the stream, a private key needs to be provided as well. If no keys are
            provided by this function, the data blocks will not be encrypted, unless encryption
            keys are provided on a per-block basis. Per block basis encrption keys override
            stream level encryption keys.
        '''
        pass


    def create(self, fhandle, manifest_block):
        '''
            Open a new stream, based on the file-like handle. The stream must be empty.
        '''

        handle.seek(BEGIN)
        offset = handle.tell()

        if offset != 0:
            raise ExceptionFileNotEmpty

        if not manifest_block:
            raise ExceptionMissingManifestBlock

        self.fhandle = fhandle
        self.append(ujson.dumps(manifest_block))


    def create(self, filename, manifest_block):
        '''
            Open a new file based stream. The stream file must not exist.
        '''

        if os.path.exists(filename):
            raise IOError("File exists")

        if not manifest_block:
            raise ExceptionMissingManifestBlock

        self.fhandle = open(filename, "wb")
        self.append(ujson.dumps(manifest_block))


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
            block_size = struct.unpack("<Q", self.fhandle.read(self.BLOCK_SIZE_BYTES))[0]
            if block_size < self.BLOCK_SIZE_BYTES + 1 or block_size > self.MAX_BLOCK_SIZE:
                raise ExceptionCorruptStream

            self.fhandle.seek(block_size - self.BLOCK_SIZE_BYTES, 1)
        except IOError:
            self.current_block = self.current_block_pos = -1
            return 0

        self.current_block_pos = self.fhandle.tell()
        self.current_block += 1

        return block_size

    def _validate_and_parse_block(self, block):
        return block
   

    def read_block(self, index):
        '''
            Read and return the requested block. 
        '''

        if self.current_block >= 0 and self.current_block != index:
            self._seek_to_block(index)

        try:
            block_size_raw = self.fhandle.read(self.BLOCK_SIZE_BYTES)
        except IOError as err:
            raise ExceptionCorruptStream(err)

        num_read = len(block_size_raw)
        if num_read == 0:
            return None

        if num_read < self.BLOCK_SIZE_BYTES:
            raise ExceptionCorruptStream

        try:
            block_size = struct.unpack("<Q", block_size_raw)[0]
            if block_size < self.BLOCK_SIZE_BYTES + 1 or block_size > self.MAX_BLOCK_SIZE:
                raise ExceptionCorruptStream

            block = self.fhandle.read(block_size - self.BLOCK_SIZE_BYTES);
        except IOError:
            raise ExceptionCorruptStream
            
        self.current_block = index + 1
        self.current_block_pos = self.fhandle.tell()

        return self._validate_and_parse_block(block)


    def append(self, block, public_key=None, private_key=None):
        '''
            Append the block to this stream.
        '''

        if not self.stream_signature_key_private:
            raise(ExceptionNoPrivateSignatureKey)

        if (public_key or private_key) and (not private_key or not public_key):
            raise(ExceptionMissingContentKey)


        try:
            self.fhandle.seek(0, 2)
            self.fhandle.write(struct.pack("<Q", len(block) + self.BLOCK_SIZE_BYTES))
            self.fhandle.write(block)
        except IOError as err:
            raise ExceptionWriteError(err)


if __name__ == "__main__":
   s = Stream("public sig")
   s.create("test.im", { 'type' : Stream.MANIFEST_BLOCK } )
   s.set_stream_signature_keys("public sig", "private sig")
   s.append("There is shite here.")
   s.append("Even more shit!")
   s.close()
