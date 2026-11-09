"""Backend interface (``ParagonIE\\CipherSweet\\Contract\\BackendInterface``)."""

from __future__ import annotations

import abc
from typing import Any, Mapping, Optional

from .._util import b64url_decode, hash_equals, to_bytes
from ..exceptions import InvalidCiphertextException
from ..key import SymmetricKey


class Backend(abc.ABC):
    """A cryptographic backend.

    Implementations must be stateless: one instance can be shared between
    engines and threads.
    """

    MAGIC_HEADER: str = ""

    #: True when the backend is safe for multi-tenant use (FIPS, Boring).
    multi_tenant_safe: bool = False

    @abc.abstractmethod
    def encrypt(self, plaintext: bytes, key: SymmetricKey, aad: bytes = b"") -> str:
        """Encrypt *plaintext*; returns ``prefix + base64url(...)``."""

    @abc.abstractmethod
    def decrypt(self, ciphertext: Any, key: SymmetricKey, aad: bytes = b"") -> bytes:
        """Verify and decrypt a ciphertext produced by :meth:`encrypt`."""

    @abc.abstractmethod
    def blind_index_fast(
        self, plaintext: bytes, key: SymmetricKey, bit_length: Optional[int] = None
    ) -> bytes:
        """Fast (non-password-hashing) blind index, raw bytes."""

    @abc.abstractmethod
    def blind_index_slow(
        self,
        plaintext: bytes,
        key: SymmetricKey,
        bit_length: Optional[int] = None,
        config: Optional[Mapping[str, Any]] = None,
    ) -> bytes:
        """Slow (password-hashing) blind index, raw bytes."""

    @abc.abstractmethod
    def get_index_type_column(self, table_name: str, field_name: str, index_name: str) -> str:
        """Short identifier used for typed blind indexes."""

    @abc.abstractmethod
    def derive_key_from_password(self, password: bytes, salt: bytes) -> SymmetricKey:
        """Derive a symmetric key from a password."""

    def get_prefix(self) -> str:
        return self.MAGIC_HEADER

    # -- helpers ---------------------------------------------------------

    def _split_ciphertext(self, ciphertext: Any) -> bytes:
        data = to_bytes(ciphertext)
        header = self.MAGIC_HEADER.encode("ascii")
        if not hash_equals(data[: len(header)], header):
            raise InvalidCiphertextException("Invalid ciphertext header.")
        try:
            return b64url_decode(data[len(header) :])
        except ValueError as exc:
            raise InvalidCiphertextException("Invalid ciphertext encoding.") from exc

    def __repr__(self) -> str:
        return f"{type(self).__name__}()"
