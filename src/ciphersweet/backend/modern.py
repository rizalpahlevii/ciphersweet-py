"""``ModernCrypto`` backend: XChaCha20-Poly1305 + BLAKE2b + Argon2id."""

from __future__ import annotations

import os
from typing import Any, Mapping, Optional

import nacl.bindings
import nacl.exceptions
import nacl.pwhash

from .._util import and_mask, b64url_encode, base32_encode_unpadded, generichash, pack
from ..exceptions import CipherSweetException, InvalidCiphertextException
from ..key import SymmetricKey
from .base import Backend

# PHP reads these from ParagonIE_Sodium_Compat, which defines the *Argon2i*
# interactive limits (4 passes, 32 MiB) even though the hash is Argon2id.
# Using libsodium's own Argon2id constants (2 passes, 64 MiB) would produce
# different blind indexes.
OPSLIMIT_INTERACTIVE = 4
MEMLIMIT_INTERACTIVE = 33554432


def _sodium_blind_index_fast(plaintext: bytes, key: SymmetricKey, bit_length: Optional[int]) -> bytes:
    if bit_length is None:
        bit_length = 256
    if bit_length > 512:
        raise CipherSweetException("Output length is too high")
    hash_length = bit_length >> 3 if bit_length > 256 else 32
    digest = generichash(plaintext, key.get_raw_key(), hash_length)
    return and_mask(digest, bit_length)


def _sodium_blind_index_slow(
    plaintext: bytes,
    key: SymmetricKey,
    bit_length: Optional[int],
    config: Optional[Mapping[str, Any]],
) -> bytes:
    config = config or {}
    ops = OPSLIMIT_INTERACTIVE
    mem = MEMLIMIT_INTERACTIVE
    if config.get("opslimit") is not None and config["opslimit"] > ops:
        ops = int(config["opslimit"])
    if config.get("memlimit") is not None and config["memlimit"] > mem:
        mem = int(config["memlimit"])
    if bit_length is None:
        bit_length = 256
    length = max(bit_length >> 3, 16)
    salt = generichash(key.get_raw_key(), b"", 16)
    digest = nacl.pwhash.argon2id.kdf(length, plaintext, salt, opslimit=ops, memlimit=mem)
    return and_mask(digest, bit_length)


def _sodium_index_type_column(table_name: str, field_name: str, index_name: str) -> str:
    salt = generichash(table_name.encode("utf-8"), b"", 16)
    digest = nacl.bindings.crypto_shorthash_siphash24(pack([field_name, index_name]), salt)
    return base32_encode_unpadded(digest)


def _sodium_derive_key_from_password(password: bytes, salt: bytes) -> SymmetricKey:
    # PHP uses the global SODIUM_CRYPTO_PWHASH_*_INTERACTIVE constants here
    # (libsodium's Argon2id values: 2 passes, 64 MiB) and the default algorithm.
    return SymmetricKey(
        nacl.pwhash.argon2id.kdf(
            32,
            password,
            salt,
            opslimit=nacl.pwhash.argon2id.OPSLIMIT_INTERACTIVE,
            memlimit=nacl.pwhash.argon2id.MEMLIMIT_INTERACTIVE,
        )
    )


class ModernCrypto(Backend):
    """``nacl:`` backend. Wire-compatible with PHP ``ModernCrypto``."""

    MAGIC_HEADER = "nacl:"
    NONCE_SIZE = 24

    def encrypt(self, plaintext: bytes, key: SymmetricKey, aad: bytes = b"") -> str:
        nonce = os.urandom(self.NONCE_SIZE)
        ct = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
            bytes(plaintext), nonce + aad, nonce, key.get_raw_key()
        )
        return self.MAGIC_HEADER + b64url_encode(nonce + ct)

    def decrypt(self, ciphertext: Any, key: SymmetricKey, aad: bytes = b"") -> bytes:
        decoded = self._split_ciphertext(ciphertext)
        if len(decoded) < self.NONCE_SIZE + 16:
            raise InvalidCiphertextException("Message is too short.")
        nonce = decoded[: self.NONCE_SIZE]
        encrypted = decoded[self.NONCE_SIZE :]
        try:
            return nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
                encrypted, nonce + aad, nonce, key.get_raw_key()
            )
        except nacl.exceptions.CryptoError as exc:
            raise InvalidCiphertextException("Invalid ciphertext") from exc

    def blind_index_fast(self, plaintext, key, bit_length=None):
        return _sodium_blind_index_fast(plaintext, key, bit_length)

    def blind_index_slow(self, plaintext, key, bit_length=None, config=None):
        return _sodium_blind_index_slow(plaintext, key, bit_length, config)

    def get_index_type_column(self, table_name, field_name, index_name):
        return _sodium_index_type_column(table_name, field_name, index_name)

    def derive_key_from_password(self, password, salt):
        return _sodium_derive_key_from_password(password, salt)
