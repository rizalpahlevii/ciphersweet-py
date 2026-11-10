"""Key/backend rotation helpers (``ParagonIE\\CipherSweet\\KeyRotation``)."""

from __future__ import annotations

from typing import Any, Mapping

from ._util import hash_equals, to_bytes
from .encrypted_field import EncryptedField
from .encrypted_multi_rows import EncryptedMultiRows
from .encrypted_row import EncryptedRow
from .exceptions import CipherSweetException, InvalidCiphertextException


class FieldRotator:
    """Re-encrypt a single column from an old configuration to a new one."""

    def __init__(self, old: EncryptedField, new: EncryptedField) -> None:
        self.old = old
        self.new = new

    def needs_re_encrypt(self, ciphertext: Any = "", aad: Any = "") -> bool:
        if not isinstance(ciphertext, (str, bytes)):
            raise InvalidCiphertextException("FieldRotator expects a string, not an array")
        data = to_bytes(ciphertext)
        if len(data) < 5:
            raise InvalidCiphertextException("This message is not encrypted")
        if not hash_equals(data[:5], self.new.get_engine().get_backend().get_prefix().encode()):
            return True
        try:
            self.new.decrypt_value_bytes(ciphertext, aad)
            return False
        except (CipherSweetException, ValueError):
            return True

    def prepare_for_update(self, value: Any, old_aad: Any = "", new_aad: Any = ""):
        if not isinstance(value, (str, bytes)):
            raise TypeError("FieldRotator expects a string")
        plaintext = self.old.decrypt_value_bytes(value, old_aad)
        return self.new.prepare_for_storage(plaintext, new_aad)


class RowRotator:
    """Re-encrypt a row from an old ``EncryptedRow`` configuration to a new one."""

    def __init__(self, old: EncryptedRow, new: EncryptedRow) -> None:
        self.old = old
        self.new = new

    def needs_re_encrypt(self, row: Any) -> bool:
        if not isinstance(row, Mapping):
            raise InvalidCiphertextException("RowRotator expects a mapping, not a string")
        try:
            self.new.decrypt_row(row)
            return False
        except (CipherSweetException, ValueError, TypeError):
            return True

    def prepare_for_update(self, row: Any):
        if not isinstance(row, Mapping):
            raise InvalidCiphertextException("RowRotator expects a mapping, not a string")
        return self.new.prepare_row_for_storage(self.old.decrypt_row(row))


class MultiRowsRotator:
    """Re-encrypt several tables' rows at once."""

    def __init__(self, old: EncryptedMultiRows, new: EncryptedMultiRows) -> None:
        self.old = old
        self.new = new

    def needs_re_encrypt(self, rows: Any) -> bool:
        if not isinstance(rows, Mapping):
            raise InvalidCiphertextException("MultiRowsRotator expects a mapping, not a string")
        try:
            self.new.decrypt_many_rows(rows)
            return False
        except (CipherSweetException, ValueError, TypeError):
            return True

    def prepare_for_update(self, rows: Any):
        if not isinstance(rows, Mapping):
            raise InvalidCiphertextException("MultiRowsRotator expects a mapping, not a string")
        return self.new.prepare_for_storage(self.old.decrypt_many_rows(rows))
