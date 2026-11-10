"""``FIPSCrypto`` backend: AES-256-CTR + HMAC-SHA-384 + PBKDF2-SHA-384."""

from __future__ import annotations

import hashlib
import os
from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .._util import (
    and_mask,
    b64url_encode,
    base32_encode_unpadded,
    hash_equals,
    hkdf,
    hmac_sha384,
    pack,
)
from ..exceptions import InvalidCiphertextException
from ..key import SymmetricKey
from .base import Backend


def aes256ctr(data: bytes, key: bytes, nonce: bytes) -> bytes:
    if not data:
        return b""
    enc = Cipher(algorithms.AES(key), modes.CTR(nonce)).encryptor()
    return enc.update(data) + enc.finalize()


class FIPSCrypto(Backend):
    """``fips:`` backend. Wire-compatible with PHP ``FIPSCrypto``."""

    MAGIC_HEADER = "fips:"
    MAC_SIZE = 48
    SALT_SIZE = 32
    NONCE_SIZE = 16
    multi_tenant_safe = True

    def _mac(self, mac_key: bytes, salt: bytes, nonce: bytes, ct: bytes, aad: bytes) -> bytes:
        return hmac_sha384(mac_key, pack([self.MAGIC_HEADER, salt, nonce, ct]) + aad)

    def encrypt(self, plaintext: bytes, key: SymmetricKey, aad: bytes = b"") -> str:
        salt = os.urandom(self.SALT_SIZE)
        nonce = os.urandom(self.NONCE_SIZE)
        enc_key = hkdf(key.get_raw_key(), salt, b"AES-256-CTR")
        mac_key = hkdf(key.get_raw_key(), salt, b"HMAC-SHA-384")
        ct = aes256ctr(bytes(plaintext), enc_key, nonce)
        mac = self._mac(mac_key, salt, nonce, ct, aad)
        return self.MAGIC_HEADER + b64url_encode(salt + nonce + mac + ct)

    def decrypt(self, ciphertext: Any, key: SymmetricKey, aad: bytes = b"") -> bytes:
        decoded = self._split_ciphertext(ciphertext)
        if len(decoded) < self.MAC_SIZE + self.NONCE_SIZE + self.SALT_SIZE:
            raise InvalidCiphertextException("Message is too short.")
        salt = decoded[: self.SALT_SIZE]
        nonce = decoded[self.SALT_SIZE : self.SALT_SIZE + self.NONCE_SIZE]
        off = self.SALT_SIZE + self.NONCE_SIZE
        mac = decoded[off : off + self.MAC_SIZE]
        ct = decoded[off + self.MAC_SIZE :]
        enc_key = hkdf(key.get_raw_key(), salt, b"AES-256-CTR")
        mac_key = hkdf(key.get_raw_key(), salt, b"HMAC-SHA-384")
        if not hash_equals(self._mac(mac_key, salt, nonce, ct, aad), mac):
            raise InvalidCiphertextException("Invalid MAC")
        return aes256ctr(ct, enc_key, nonce)

    @staticmethod
    def _pbkdf2(plaintext: bytes, key: SymmetricKey, iterations: int, bit_length: int) -> bytes:
        length = bit_length >> 3
        # PHP's hash_pbkdf2 treats a length of 0 as "full digest".
        return hashlib.pbkdf2_hmac("sha384", plaintext, key.get_raw_key(), iterations, length or None)

    def blind_index_fast(self, plaintext, key, bit_length=None):
        if bit_length is None:
            bit_length = 256
        return and_mask(self._pbkdf2(plaintext, key, 1, bit_length), bit_length)

    def blind_index_slow(self, plaintext, key, bit_length=None, config=None):
        if bit_length is None:
            bit_length = 256
        iterations = 50000
        config = config or {}
        if config.get("iterations") is not None and config["iterations"] > 50000:
            iterations = int(config["iterations"])
        return and_mask(self._pbkdf2(plaintext, key, iterations, bit_length), bit_length)

    def get_index_type_column(self, table_name, field_name, index_name):
        digest = hmac_sha384(table_name.encode("utf-8"), pack([field_name, index_name]))
        return base32_encode_unpadded(digest[:8])

    def derive_key_from_password(self, password, salt):
        return SymmetricKey(hashlib.pbkdf2_hmac("sha384", password, salt, 100000, 32))
