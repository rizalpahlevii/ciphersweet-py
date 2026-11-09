"""``EncryptedField``: encrypt one column and compute its blind indexes."""

from __future__ import annotations

from typing import Any, Dict, Optional, Union

from ._util import hex_encode, to_bytes
from .aad import AAD, AADLike
from .backend import Backend
from .blind_index import BlindIndex
from .engine import CipherSweet
from .exceptions import (
    BlindIndexNameCollisionException,
    BlindIndexNotFoundException,
    CipherSweetException,
)
from .key import SymmetricKey

IndexValue = Union[str, Dict[str, str]]


class EncryptedField:
    """Searchable encryption for a single column.

    >>> field = EncryptedField(engine, "contacts", "ssn")
    >>> field.add_blind_index(BlindIndex("contact_ssn_last_four", [LastFourDigits()], 16, True))
    >>> ciphertext, indexes = field.prepare_for_storage("123-45-6789")
    """

    def __init__(
        self,
        engine: CipherSweet,
        table_name: str = "",
        field_name: str = "",
        use_typed_indexes: bool = False,
    ) -> None:
        self.engine = engine
        self.table_name = table_name
        self.field_name = field_name
        self.typed_indexes = use_typed_indexes
        self.blind_indexes: Dict[str, BlindIndex] = {}
        self._key = engine.get_field_symmetric_key(table_name, field_name)

    def set_active_tenant(self, tenant: Union[str, int]) -> EncryptedField:
        if not self.engine.is_multi_tenant_supported():
            raise CipherSweetException("This is only available for multi-tenant-aware engines/providers.")
        self.engine.set_active_tenant(tenant)
        self._key = self.engine.get_field_symmetric_key(self.table_name, self.field_name)
        return self

    # -- encryption ------------------------------------------------------

    def prepare_for_storage(self, plaintext: Union[str, bytes], aad: AADLike = "") -> tuple:
        """Return ``(ciphertext, {index_name: index_value})``."""
        return self.encrypt_value(plaintext, aad), self.get_all_blind_indexes(plaintext)

    def encrypt_value(self, plaintext: Union[str, bytes], aad: AADLike = "") -> str:
        return self.engine.get_backend().encrypt(
            to_bytes(plaintext), self._key, AAD.literal(aad).canonicalize()
        )

    def decrypt_value_bytes(self, ciphertext: Union[str, bytes], aad: AADLike = "") -> bytes:
        return self.engine.get_backend().decrypt(ciphertext, self._key, AAD.literal(aad).canonicalize())

    def decrypt_value(self, ciphertext: Union[str, bytes], aad: AADLike = "") -> str:
        """Decrypt and UTF-8 decode. Use :meth:`decrypt_value_bytes` for binary data."""
        return self.decrypt_value_bytes(ciphertext, aad).decode("utf-8")

    # -- blind indexes ---------------------------------------------------

    def get_all_blind_indexes(self, plaintext: Union[str, bytes]) -> Dict[str, IndexValue]:
        root = self.engine.get_blind_index_root_key(self.table_name, self.field_name)
        return {name: self._format(name, self._raw(plaintext, name, root)) for name in self.blind_indexes}

    def get_blind_index(self, plaintext: Union[str, bytes], name: str) -> IndexValue:
        return self._format(name, self._raw(plaintext, name))

    def get_blind_index_raw(self, plaintext: Union[str, bytes], name: str) -> bytes:
        return self._raw(plaintext, name)

    def _format(self, name: str, raw: bytes) -> IndexValue:
        if self.typed_indexes:
            return {"type": self.get_blind_index_type(name), "value": hex_encode(raw)}
        return hex_encode(raw)

    def _raw(self, plaintext: Any, name: str, root: Optional[SymmetricKey] = None) -> bytes:
        if name not in self.blind_indexes:
            raise BlindIndexNotFoundException(f"Blind index {name} not found")
        index = self.blind_indexes[name]
        sub_key = self.engine.get_blind_index_key(self.table_name, self.field_name, name, root)
        backend = self.engine.get_backend()
        transformed = index.get_transformed(to_bytes(plaintext))
        if index.get_fast_hash():
            return backend.blind_index_fast(transformed, sub_key, index.get_filter_bit_length())
        return backend.blind_index_slow(
            transformed, sub_key, index.get_filter_bit_length(), index.get_hash_config()
        )

    def get_blind_index_objects(self) -> Dict[str, BlindIndex]:
        return self.blind_indexes

    def get_blind_index_type(self, name: str) -> str:
        return self.engine.get_index_type_column(self.table_name, self.field_name, name)

    def get_blind_index_types(self) -> Dict[str, str]:
        return {name: self.get_blind_index_type(name) for name in self.blind_indexes}

    def add_blind_index(self, index: BlindIndex, name: Optional[str] = None) -> EncryptedField:
        name = index.get_name() if name is None else name
        if name in self.blind_indexes:
            raise BlindIndexNameCollisionException(f"Index {name} already defined")
        self.blind_indexes[name] = index
        return self

    # -- settings --------------------------------------------------------

    def get_backend(self) -> Backend:
        return self.engine.get_backend()

    def get_engine(self) -> CipherSweet:
        return self.engine

    def get_flat_indexes(self) -> bool:
        return not self.typed_indexes

    def get_typed_indexes(self) -> bool:
        return self.typed_indexes

    def set_flat_indexes(self, flat: bool) -> EncryptedField:
        self.typed_indexes = not flat
        return self

    def set_typed_indexes(self, typed: bool) -> EncryptedField:
        self.typed_indexes = typed
        return self
