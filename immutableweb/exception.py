# TODO: Remove many of these and use built in ones
class InvalidKeyPair(Exception):
    pass

class MissingKey(Exception):
    pass

class InvalidState(Exception):
    pass

class StreamCorrupt(Exception):
    pass

class HashFailure(Exception):
    pass

class SignatureFailure(Exception):
    pass
