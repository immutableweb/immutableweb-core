import os
import sys

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

class Stream(object):

    def __init_():
        self.stream_signature_key_public = None
        self.stream_signature_key_private = None
        self.stream_content_key_public = None
        self.stream_content_key_private = None

        # Keep track of the current block ready to read, or -1 if not set.
        self.current_block = -1

        # Keep track of the current block position ready to read, or -1 if not set.
        self.current_block_pos = -1


    def set_stream_signatue_keys(public_key, private_key = None):
        '''
            Set the public key for verifying data in the stream. Optionally, 
            set the private key for appending new data to the stream. Only needed if
            you intend to append more blocks. At minimum, a public key for verifying
            the stream is required.
        '''


    def stream_content_keys(public_key, private_key = None):
        ''' 
            Set the encyption keys to be used by the whole stream. If the caller plans to 
            append to the stream, a private key needs to be provided as well. If no keys are
            provided by this function, the data blocks will not be encrypted, unless encryption
            keys are provided on a per-block basis. Per block basis encrption keys override
            stream level encryption keys.
        '''
        pass


    def create(fhandle, manifest_block):
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


    def create(filename, manifest_block):
        '''
            Open a new file based stream. The stream file must not exist.
        '''

        if os.path.exists(filename):
            except IOErrr("File exists")

        if not manifest_block:
            raise ExceptionMissingManifestBlock

        self.fhandle = open(filename, "wb")


    def open(filename):
        '''
            Open a stream using a filename
        '''

        self.fhandle = open(filename, "rb")
        if not self.stream_signature_key_public:
            raise ExceptionMissingStreamSignatureKey

        self.manifest_block = self.read_block(0)


    def open(fhandle):
        ''' 
            Open a file given a file-like object
        '''

        if not self.stream_signature_key_public:
            raise ExceptionMissingStreamSignatureKey

        self.manifest_block = self.read_block(0)


    def close(close_handle=True):
        '''
            Close the stream, flushing bits as necessary. Close the associated file if close_file is True.
        '''
        if close_handle:
            self.handle.close()
        else:
            self.fhandle.flush()

        self.fhandle = None


    def _seek_to_beginning():
        '''
            Reset the current block index/position to he beginning
        '''
        self.current_block = self.current_block_pos = 0
        self.fhandle.seek(0)


    def _skip_next_block():
        block_size = struct.unpack("FIX ME", self.read(8))
        self.fhandle.seek(block_size - 8, CUR_POS)

    
    def read_block(index):
        '''
            Read and return the requested block. 
        '''

        # The fileposition will always be left after the last block was read, re
        if self.current_block == -1 or self.current_block ~= index)
            self.seek_to_block(index)




    def append(block, public_key=None, private_key=None):
        '''
            Append the block to this stream.
        '''

        if not self.self.stream_signature_key_private:
            raise(ExceptionNoPrivateSignatureKey)

        if (public_key or private_key) and (!private_key or !public_key):
            raise(ExceptionMissingContentKey)

            
