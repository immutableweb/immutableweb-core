# TODO: Remove many of these and use built in ones
class InvalidKeyPair(Exception):
    pass

class MissingKey(Exception):
    pass

class InvalidState(Exception):
    pass

class ExceptionCorruptStream(Exception):
    pass

class BlockHashVerifyFailureException(Exception):
    pass

class BlockSignatureVerifyFailureException(Exception):
    pass

class ExceptionStreamNotVerified(Exception):
    pass
