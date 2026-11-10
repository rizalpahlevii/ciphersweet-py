"""Exception hierarchy, mirroring ``ParagonIE\\CipherSweet\\Exception``."""


class CipherSweetException(Exception):
    """Base class for every error raised by this library."""


class ArrayKeyException(CipherSweetException):
    """A required column is missing from a row."""


class BlindIndexNameCollisionException(CipherSweetException):
    """Two blind indexes with the same name were added to one field."""


class BlindIndexNotFoundException(CipherSweetException):
    """The requested blind index is not defined."""


class CryptoOperationException(CipherSweetException):
    """A cryptographic operation could not be performed."""


class EmptyFieldException(CipherSweetException):
    """A field expected by ``decrypt_row`` is not present."""


class InvalidAADException(CipherSweetException):
    """AAD configuration is invalid (e.g. an encrypted field used as AAD)."""


class InvalidCiphertextException(CipherSweetException):
    """The ciphertext is malformed, was tampered with, or the key/AAD is wrong."""


class JsonMapException(CipherSweetException):
    """A JSON field map is invalid."""


class KeyProviderException(CipherSweetException):
    """A key provider could not supply a key."""
