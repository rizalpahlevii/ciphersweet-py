"""``BoringCrypto`` backend: XChaCha20 + BLAKE2b-MAC (PHP CipherSweet v3+ default)."""

from __future__ import annotations

import os
from typing import Any

from .._util import b64url_encode, generichash, hash_equals
from .._xchacha import xchacha20_xor
from ..exceptions import InvalidCiphertextException
from ..key import SymmetricKey
from .base import Backend
from .modern import (
    _sodium_blind_index_fast,
    _sodium_blind_index_slow,
    _sodium_derive_key_from_password,
    _sodium_index_type_column,
)


class BoringCrypto(Backend):
    """``brng:`` backend. Wire-compatible with PHP ``BoringCrypto``.

    This is the default backend of ``paragonie/ciphersweet`` when none is
    given. (It has nothing to do with Google's BoringSSL.)
    """

    MAGIC_HEADER = "brng:"
    NONCE_SIZE = 24
    MAC_SIZE = 32
    multi_tenant_safe = True

    @staticmethod
    def _encryption_key(key: SymmetricKey) -> bytes:
        return generichash(b"message-encryption", key.get_raw_key(), 32)

    @staticmethod
    def _integrity_key(key: SymmetricKey) -> bytes:
        return generichash(b"message-integrity", key.get_raw_key(), 32)

    def _mac(self, key: SymmetricKey, nonce: bytes, aad: bytes, ciphertext: bytes) -> bytes:
        # PHP concatenates the *decimal* string form of each length.
        msg = b"".join(
            [
                self.MAGIC_HEADER.encode("ascii"),
                nonce,
                str(len(aad)).encode("ascii"),
                aad,
                str(len(ciphertext)).encode("ascii"),
                ciphertext,
            ]
        )
        return generichash(msg, self._integrity_key(key), self.MAC_SIZE)

    def encrypt(self, plaintext: bytes, key: SymmetricKey, aad: bytes = b"") -> str:
        nonce = os.urandom(self.NONCE_SIZE)
        ct = xchacha20_xor(bytes(plaintext), nonce, self._encryption_key(key))
        mac = self._mac(key, nonce, aad, ct)
        return self.MAGIC_HEADER + b64url_encode(nonce + mac + ct)

    def decrypt(self, ciphertext: Any, key: SymmetricKey, aad: bytes = b"") -> bytes:
        decoded = self._split_ciphertext(ciphertext)
        if len(decoded) < self.NONCE_SIZE + self.MAC_SIZE:
            raise InvalidCiphertextException("Message is too short.")
        nonce = decoded[: self.NONCE_SIZE]
        stored = decoded[self.NONCE_SIZE : self.NONCE_SIZE + self.MAC_SIZE]
        encrypted = decoded[self.NONCE_SIZE + self.MAC_SIZE :]
        if not hash_equals(self._mac(key, nonce, aad, encrypted), stored):
            raise InvalidCiphertextException("Invalid ciphertext")
        return xchacha20_xor(encrypted, nonce, self._encryption_key(key))

    def blind_index_fast(self, plaintext, key, bit_length=None):
        return _sodium_blind_index_fast(plaintext, key, bit_length)

    def blind_index_slow(self, plaintext, key, bit_length=None, config=None):
        return _sodium_blind_index_slow(plaintext, key, bit_length, config)

    def get_index_type_column(self, table_name, field_name, index_name):
        return _sodium_index_type_column(table_name, field_name, index_name)

    def derive_key_from_password(self, password, salt):
        return _sodium_derive_key_from_password(password, salt)
