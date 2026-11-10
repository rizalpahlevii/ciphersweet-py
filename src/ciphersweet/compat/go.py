"""Interop with `ciphersweet-go <https://github.com/rizalpahlevii/ciphersweet-go>`_.

ciphersweet-go's ``NaCl`` backend matches PHP for encryption and fast
blind indexes, so the regular :class:`~ciphersweet.ModernCrypto` reads its
``nacl:`` data. Two things differ and are covered here:

* :class:`GoBoringCrypto` reads and writes the Go-only ``boring:`` format
  (AES-256-GCM, HKDF-SHA256 key derivation). It is **not** PHP's
  ``brng:`` BoringCrypto.
* Go's slow (Argon2id) blind indexes default to 512 MiB / 2 lanes instead of
  libsodium's interactive 64 MiB / 1 lane. :class:`GoModernCrypto`
  reproduces the Go parameters.

Both slow-index paths need the optional ``argon2-cffi`` dependency:
``pip install "ciphersweet-py[go]"``.

Note that ciphersweet-go's ``EncryptedRow`` stores booleans and numbers as
their text form rather than CipherSweet's typed encoding, so decrypt Go rows
with text fields and convert the values yourself.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Mapping, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .._util import and_mask, generichash, hkdf, hmac_sha256, to_bytes
from ..backend.base import Backend
from ..backend.modern import ModernCrypto
from ..exceptions import CipherSweetException, InvalidCiphertextException
from ..key import SymmetricKey


@dataclass(frozen=True)
class GoArgonConfig:
    """``argon.Config`` from ciphersweet-go (``DefaultConfig()`` values)."""

    time_cost: int = 2
    memory_cost_kib: int = 512 * 1024
    parallelism: int = 2

    @classmethod
    def from_mapping(cls, config: Optional[Mapping[str, Any]]) -> GoArgonConfig:
        if not config:
            return cls()
        return cls(
            int(config.get("time_cost", cls.time_cost)),
            int(config.get("memory_cost_kib", cls.memory_cost_kib)),
            int(config.get("parallelism", cls.parallelism)),
        )


def _argon2id(password: bytes, salt: bytes, length: int, cfg: GoArgonConfig) -> bytes:
    try:
        from argon2.low_level import Type, hash_secret_raw
    except ImportError as exc:  # pragma: no cover - depends on environment
        raise CipherSweetException(
            "Go-compatible slow blind indexes need argon2-cffi: pip install 'ciphersweet-py[go]'"
        ) from exc
    return hash_secret_raw(
        password,
        salt,
        time_cost=cfg.time_cost,
        memory_cost=cfg.memory_cost_kib,
        parallelism=cfg.parallelism,
        hash_len=length,
        type=Type.ID,
    )


def _check_bits(bits: int) -> None:
    if bits < 1 or bits > 512:
        raise CipherSweetException(f"outputBits {bits} out of range [1, 512]")


class GoModernCrypto(ModernCrypto):
    """``nacl:`` backend with ciphersweet-go's Argon2id parameters for slow
    blind indexes. Everything else is identical to :class:`ModernCrypto`.

    ``config`` on a slow :class:`~ciphersweet.BlindIndex` may set
    ``time_cost``, ``memory_cost_kib`` and ``parallelism``.
    """

    def blind_index_slow(self, plaintext, key, bit_length=None, config=None):
        bits = 256 if bit_length is None else bit_length
        _check_bits(bits)
        length = max((bits + 7) // 8, 16)
        salt = generichash(key.get_raw_key(), b"", 16)
        return and_mask(_argon2id(plaintext, salt, length, GoArgonConfig.from_mapping(config)), bits)


class GoBoringCrypto(Backend):
    """ciphersweet-go's ``boring:`` backend (AES-256-GCM).

    Key hierarchy (replaces CipherSweet's HKDF-SHA384 one):

    * field key: ``HKDF-SHA256(root, info="field|<table>|<field>")``
    * index key: ``HKDF-SHA256(root, info="index|<table>|<field>|<index>")``
    * message key: ``HKDF-SHA256(field_key, info="encrypt" ["|" + aad])``
    """

    MAGIC_HEADER = "boring:"
    NONCE_SIZE = 12
    TAG_SIZE = 16

    @staticmethod
    def _hkdf(secret: bytes, info: bytes) -> bytes:
        return hkdf(secret, None, info, 32, "sha256")

    # hooks used by CipherSweet / EncryptedField / EncryptedRow
    def derive_field_key(self, root: SymmetricKey, table: str, field: str) -> SymmetricKey:
        return SymmetricKey(
            self._hkdf(root.get_raw_key(), b"field|" + to_bytes(table) + b"|" + to_bytes(field))
        )

    def derive_blind_index_key(self, root: SymmetricKey, table: str, field: str, index: str) -> SymmetricKey:
        info = b"index|" + b"|".join(to_bytes(x) for x in (table, field, index))
        return SymmetricKey(self._hkdf(root.get_raw_key(), info))

    def _message_key(self, key: SymmetricKey, aad: bytes) -> bytes:
        info = b"encrypt" + (b"|" + aad if aad else b"")
        return self._hkdf(key.get_raw_key(), info)

    def encrypt(self, plaintext: bytes, key: SymmetricKey, aad: bytes = b"") -> str:
        nonce = os.urandom(self.NONCE_SIZE)
        sealed = AESGCM(self._message_key(key, aad)).encrypt(nonce, bytes(plaintext), aad or None)
        import base64

        return self.MAGIC_HEADER + base64.urlsafe_b64encode(nonce + sealed).decode().rstrip("=")

    def decrypt(self, ciphertext: Any, key: SymmetricKey, aad: bytes = b"") -> bytes:
        raw = self._split_ciphertext(ciphertext)
        if len(raw) < self.NONCE_SIZE + self.TAG_SIZE:
            raise InvalidCiphertextException("ciphertext too short")
        try:
            return AESGCM(self._message_key(key, aad)).decrypt(
                raw[: self.NONCE_SIZE], raw[self.NONCE_SIZE :], aad or None
            )
        except InvalidTag as exc:
            raise InvalidCiphertextException("authentication failed") from exc

    def blind_index_fast(self, plaintext, key, bit_length=None):
        bits = 256 if bit_length is None else bit_length
        _check_bits(bits)
        return and_mask(hmac_sha256(key.get_raw_key(), plaintext), bits)

    def blind_index_slow(self, plaintext, key, bit_length=None, config=None):
        bits = 256 if bit_length is None else bit_length
        _check_bits(bits)
        length = (bits + 7) // 8
        return and_mask(
            _argon2id(plaintext, key.get_raw_key(), length, GoArgonConfig.from_mapping(config)), bits
        )

    def get_index_type_column(self, table_name, field_name, index_name):
        raise CipherSweetException("ciphersweet-go has no typed indexes for the boring backend")

    def derive_key_from_password(self, password, salt):
        raise CipherSweetException("Not supported by ciphersweet-go's boring backend")


__all__ = ["GoArgonConfig", "GoBoringCrypto", "GoModernCrypto"]
