"""Symmetric key wrapper (``ParagonIE\\CipherSweet\\Backend\\Key\\SymmetricKey``)."""

from __future__ import annotations


class SymmetricKey:
    """An opaque wrapper around raw key bytes.

    The ``repr`` never reveals key material.
    """

    __slots__ = ("_key",)

    def __init__(self, key_material: bytes) -> None:
        if not isinstance(key_material, (bytes, bytearray)):
            raise TypeError("SymmetricKey expects bytes")
        self._key = bytes(key_material)

    def get_raw_key(self) -> bytes:
        return self._key

    raw = property(get_raw_key)

    def __len__(self) -> int:
        return len(self._key)

    def __repr__(self) -> str:
        return "SymmetricKey(<redacted>)"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SymmetricKey):
            return NotImplemented
        import hmac

        return hmac.compare_digest(self._key, other._key)

    def __hash__(self) -> int:  # keys are not meant to be dict keys
        raise TypeError("SymmetricKey is unhashable")
