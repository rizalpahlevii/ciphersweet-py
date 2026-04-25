"""CipherSweet engine: ties together backend + key provider."""

from .util import derive_field_enc_key


class CipherSweet:
    """
    The main CipherSweet engine.

    Usage:
        from ciphersweet import CipherSweet, NaClBackend, StringKeyProvider

        engine = CipherSweet(NaClBackend(), StringKeyProvider("your-64-hex-char-key"))
    """

    def __init__(self, backend, key_provider):
        self._backend = backend
        self._key_provider = key_provider

    @property
    def backend(self):
        return self._backend

    def get_field_symmetric_key(self, table: str, field: str) -> bytes:
        """Derive the per-field encryption key."""
        master = self._key_provider.get_symmetric_key()
        return derive_field_enc_key(master, table, field)

