"""``EncryptedRow``: encrypt several columns of one table row, with typed
values, AAD and blind/compound indexes."""

from __future__ import annotations

import enum
import json
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple, Union

from . import constants as C
from ._types import convert_from_bytes, convert_to_bytes
from ._util import enum_to_scalar, hex_encode
from .aad import AAD, AADLike
from .backend import Backend
from .blind_index import BlindIndex, CompoundIndex, FastCompoundIndex
from .engine import CipherSweet
from .exceptions import (
    ArrayKeyException,
    BlindIndexNotFoundException,
    CipherSweetException,
    EmptyFieldException,
    InvalidAADException,
)
from .json_field import EncryptedJsonField, JsonFieldMap
from .key import SymmetricKey

Row = Dict[str, Any]
IndexValue = Union[str, Dict[str, str]]

_SCALARS = (str, bytes, int, float, bool)


class EncryptedRow:
    """Searchable encryption for several columns of one table.

    This is what Laravel's ``spatie/laravel-ciphersweet`` builds for each
    model (``EncryptedRow($engine, $model->getTable())``).
    """

    def __init__(
        self,
        engine: CipherSweet,
        table_name: str,
        use_typed_indexes: bool = False,
        primary_key_column_name: Optional[str] = None,
    ) -> None:
        self.engine = engine
        self.table_name = table_name
        self.typed_indexes = use_typed_indexes
        self.primary_key_column_name = primary_key_column_name
        self.fields_to_encrypt: Dict[str, str] = {}
        self.json_maps: Dict[str, JsonFieldMap] = {}
        self.json_strict: Dict[str, bool] = {}
        self.aad_source_field: Dict[str, AAD] = {}
        self.blind_indexes: Dict[str, Dict[str, BlindIndex]] = {}
        self.compound_indexes: Dict[str, CompoundIndex] = {}
        self.permit_empty = False

    # -- schema ----------------------------------------------------------

    def add_field(
        self,
        field_name: str,
        type_: str = C.TYPE_TEXT,
        aad_source: AADLike = "",
        auto_bind_context: bool = False,
    ) -> EncryptedRow:
        self.fields_to_encrypt[field_name] = type_
        if auto_bind_context:
            if self.primary_key_column_name is not None:
                aad_source = AAD.field(aad_source).merge(AAD.field(self.primary_key_column_name))
            self.aad_source_field[field_name] = AAD.field(aad_source)
        elif aad_source:
            self.aad_source_field[field_name] = AAD.field(aad_source)
        return self

    def add_text_field(self, name: str, aad_source: AADLike = "") -> EncryptedRow:
        return self.add_field(name, C.TYPE_TEXT, aad_source)

    def add_boolean_field(self, name: str, aad_source: AADLike = "") -> EncryptedRow:
        return self.add_field(name, C.TYPE_BOOLEAN, aad_source)

    def add_float_field(self, name: str, aad_source: AADLike = "") -> EncryptedRow:
        return self.add_field(name, C.TYPE_FLOAT, aad_source)

    def add_integer_field(self, name: str, aad_source: AADLike = "") -> EncryptedRow:
        return self.add_field(name, C.TYPE_INT, aad_source)

    def add_optional_text_field(self, name: str, aad_source: AADLike = "") -> EncryptedRow:
        return self.add_field(name, C.TYPE_OPTIONAL_TEXT, aad_source)

    def add_optional_boolean_field(self, name: str, aad_source: AADLike = "") -> EncryptedRow:
        return self.add_field(name, C.TYPE_OPTIONAL_BOOLEAN, aad_source)

    def add_optional_float_field(self, name: str, aad_source: AADLike = "") -> EncryptedRow:
        return self.add_field(name, C.TYPE_OPTIONAL_FLOAT, aad_source)

    def add_optional_integer_field(self, name: str, aad_source: AADLike = "") -> EncryptedRow:
        return self.add_field(name, C.TYPE_OPTIONAL_INT, aad_source)

    def add_json_field(
        self, name: str, field_map: JsonFieldMap, aad_source: AADLike = "", strict: bool = True
    ) -> EncryptedRow:
        self.json_maps[name] = field_map
        self.json_strict[name] = strict
        return self.add_field(name, C.TYPE_JSON, aad_source)

    def add_nullable_json_field(
        self, name: str, field_map: JsonFieldMap, aad_source: AADLike = "", strict: bool = True
    ) -> EncryptedRow:
        self.json_maps[name] = field_map
        self.json_strict[name] = strict
        return self.add_field(name, C.TYPE_OPTIONAL_JSON, aad_source)

    add_optional_json_field = add_nullable_json_field

    def add_blind_index(self, column: str, index: BlindIndex) -> EncryptedRow:
        self.blind_indexes.setdefault(column, {})[index.get_name()] = index
        return self

    def add_compound_index(self, index: CompoundIndex) -> EncryptedRow:
        self.compound_indexes[index.get_name()] = index
        return self

    def create_compound_index(
        self,
        name: str,
        columns: Optional[Iterable[str]] = None,
        filter_bits: int = 256,
        fast_hash: bool = False,
        hash_config: Optional[Mapping[str, Any]] = None,
    ) -> CompoundIndex:
        index = CompoundIndex(name, columns, filter_bits, fast_hash, hash_config)
        self.add_compound_index(index)
        return index

    def create_fast_compound_index(
        self,
        name: str,
        columns: Optional[Iterable[str]] = None,
        filter_bits: int = 256,
        hash_config: Optional[Mapping[str, Any]] = None,
    ) -> CompoundIndex:
        index = FastCompoundIndex(name, columns, filter_bits, True, hash_config)
        self.add_compound_index(index)
        return index

    def set_aad_source_field(self, field_name: str, aad_source: AADLike) -> EncryptedRow:
        self.aad_source_field[field_name] = AAD.field(aad_source)
        return self

    # -- encryption ------------------------------------------------------

    def encrypt_row(self, row: Mapping[str, Any]) -> Row:
        self._throw_if_primary_key_misconfigured(row)
        out: Row = dict(row)
        backend = self.engine.get_backend()
        for field, type_ in self.fields_to_encrypt.items():
            if field not in row:
                raise ArrayKeyException(f"Expected value for column {field} on array, nothing given.")
            key = self._field_key(field)
            aad = self._canonicalize_aad(field, row)
            value = row[field]
            if type_ in C.TYPES_JSON and self.json_maps.get(field) is not None:
                enc = EncryptedJsonField(backend, key, self.json_maps[field], self.json_strict[field])
                out[field] = enc.encrypt_json(self._coax_to_document(value), aad)
                continue
            if type_ in C.TYPES_OPTIONAL and value is None:
                continue
            if type_ in C.TYPES_BOOLEAN and value is None:
                out[field] = backend.encrypt(convert_to_bytes(None, C.TYPE_BOOLEAN), key, aad)
                continue
            if isinstance(value, enum.Enum):
                value = enum_to_scalar(value)
            if not isinstance(value, _SCALARS):
                if value is None:
                    self._field_not_optional(field, type_)
                raise TypeError(f"Invalid type for {field}")
            out[field] = backend.encrypt(convert_to_bytes(value, type_), key, aad)
        if self.engine.is_multi_tenant_supported():
            return self.engine.inject_tenant_metadata(out, self.table_name)
        return out

    def decrypt_row(self, row: Mapping[str, Any]) -> Row:
        self._throw_if_primary_key_misconfigured(row)
        out: Row = dict(row)
        backend = self.engine.get_backend()
        if self.engine.is_multi_tenant_supported():
            self.engine.set_active_tenant(self.engine.get_tenant_from_row(row, self.table_name))
        for field, type_ in self.fields_to_encrypt.items():
            if field not in row:
                if not self.permit_empty:
                    raise EmptyFieldException(f"Field is not defined in row: {field}")
                continue
            value = row[field]
            if type_ in C.TYPES_OPTIONAL and value is None:
                out[field] = None
                continue
            if not isinstance(value, (str, bytes)):
                if value is None:
                    self._field_not_optional(field, type_)
                raise TypeError(f"Invalid type for {field}")
            key = self._field_key(field)
            aad = self._canonicalize_aad(field, row)
            if type_ in C.TYPES_JSON and self.json_maps.get(field) is not None:
                enc = EncryptedJsonField(backend, key, self.json_maps[field], self.json_strict[field])
                out[field] = enc.decrypt_json(value, aad)
                continue
            out[field] = convert_from_bytes(backend.decrypt(value, key, aad), type_)
        return out

    def prepare_row_for_storage(self, row: Mapping[str, Any]) -> Tuple[Row, Dict[str, IndexValue]]:
        """Return ``(encrypted_row, blind_indexes)``."""
        return self.encrypt_row(row), self.get_all_blind_indexes(row)

    def list_encrypted_fields(self) -> List[str]:
        return list(self.fields_to_encrypt)

    # -- blind indexes ---------------------------------------------------

    def get_blind_index(self, index_name: str, row: Mapping[str, Any]) -> IndexValue:
        for column, indexes in self.blind_indexes.items():
            if index_name in indexes:
                return self._calc_blind_index(row, column, indexes[index_name])
        if index_name in self.compound_indexes:
            return self._calc_compound_index(row, self.compound_indexes[index_name])
        raise BlindIndexNotFoundException(f"Blind index {index_name} not found")

    def get_all_blind_indexes(self, row: Mapping[str, Any]) -> Dict[str, IndexValue]:
        out: Dict[str, IndexValue] = {}
        for column, indexes in self.blind_indexes.items():
            for index in indexes.values():
                out[index.get_name()] = self._calc_blind_index(row, column, index)
        for name, compound in self.compound_indexes.items():
            out[name] = self._calc_compound_index(row, compound)
        return out

    def get_blind_index_objects_for_column(self, column: str) -> Dict[str, BlindIndex]:
        return self.blind_indexes.get(column, {})

    def get_blind_index_type(self, column: str, name: str) -> str:
        return self.engine.get_index_type_column(self.table_name, column, name)

    def get_compound_index_type(self, name: str) -> str:
        return self.engine.get_index_type_column(self.table_name, C.COMPOUND_SPECIAL, name)

    def get_compound_index_objects(self) -> Dict[str, CompoundIndex]:
        return self.compound_indexes

    def get_json_field_map(self, name: str) -> JsonFieldMap:
        if name not in self.fields_to_encrypt:
            raise CipherSweetException(f"Field does not exist: {name}")
        if self.fields_to_encrypt[name] != C.TYPE_JSON:
            raise CipherSweetException(f"Field {name} is not a JSON field")
        if name not in self.json_maps:
            raise CipherSweetException(f"JSON Map not found for field {name}")
        return self.json_maps[name]

    def _format(self, column: str, name: str, raw: bytes) -> IndexValue:
        if self.typed_indexes:
            return {
                "type": self.engine.get_index_type_column(self.table_name, column, name),
                "value": hex_encode(raw),
            }
        return hex_encode(raw)

    def _calc_blind_index(self, row: Mapping[str, Any], column: str, index: BlindIndex) -> IndexValue:
        return self._format(column, index.get_name(), self.calc_blind_index_raw(row, column, index))

    def _calc_compound_index(self, row: Mapping[str, Any], index: CompoundIndex) -> IndexValue:
        return self._format(C.COMPOUND_SPECIAL, index.get_name(), self.calc_compound_index_raw(row, index))

    def calc_blind_index_raw(
        self, row: Mapping[str, Any], column: str, index: BlindIndex, key: Optional[SymmetricKey] = None
    ) -> bytes:
        if column not in self.fields_to_encrypt:
            raise ArrayKeyException(f"The field {column} is not defined in this encrypted row.")
        sub_key = self.engine.get_blind_index_key(self.table_name, column, index.get_name(), key)
        value = row.get(column)
        if isinstance(value, enum.Enum):
            value = enum_to_scalar(value)
        plaintext = index.get_transformed(convert_to_bytes(value, self.fields_to_encrypt[column]))
        return self._hash(plaintext, sub_key, index)

    def calc_compound_index_raw(
        self, row: Mapping[str, Any], index: CompoundIndex, key: Optional[SymmetricKey] = None
    ) -> bytes:
        sub_key = self.engine.get_blind_index_key(self.table_name, C.COMPOUND_SPECIAL, index.get_name(), key)
        return self._hash(index.get_packed(row), sub_key, index)

    def _hash(self, plaintext: bytes, key: SymmetricKey, index: Union[BlindIndex, CompoundIndex]) -> bytes:
        backend = self.engine.get_backend()
        if index.get_fast_hash():
            return backend.blind_index_fast(plaintext, key, index.get_filter_bit_length())
        return backend.blind_index_slow(
            plaintext, key, index.get_filter_bit_length(), index.get_hash_config()
        )

    # -- settings --------------------------------------------------------

    def get_aad_source(self, field_name: str) -> AAD:
        if field_name not in self.aad_source_field:
            raise CipherSweetException(f"Source field not found for field: {field_name}")
        return self.aad_source_field[field_name]

    def get_backend(self) -> Backend:
        return self.engine.get_backend()

    def get_engine(self) -> CipherSweet:
        return self.engine

    def get_flat_indexes(self) -> bool:
        return not self.typed_indexes

    def set_flat_indexes(self, flat: bool) -> EncryptedRow:
        self.typed_indexes = not flat
        return self

    def get_typed_indexes(self) -> bool:
        return self.typed_indexes

    def set_typed_indexes(self, typed: bool) -> EncryptedRow:
        self.typed_indexes = typed
        return self

    def get_permit_empty(self) -> bool:
        return self.permit_empty

    def set_permit_empty(self, permitted: bool) -> EncryptedRow:
        self.permit_empty = permitted
        return self

    def set_primary_key_column_name(self, column_name: Optional[str] = None) -> EncryptedRow:
        self.primary_key_column_name = column_name
        return self

    # -- internals -------------------------------------------------------

    def _field_key(self, field: str) -> SymmetricKey:
        return self.engine.get_field_symmetric_key(self.table_name, field)

    def _canonicalize_aad(self, field: str, row: Mapping[str, Any]) -> bytes:
        if field not in self.aad_source_field:
            return b""
        source = self.aad_source_field[field]
        if set(self.fields_to_encrypt) & set(source.get_field_names()):
            raise InvalidAADException(f"Cannot use encrypted field as AAD - field: {field}")
        return source.canonicalize(row)

    @staticmethod
    def _coax_to_document(value: Any) -> Any:
        if value is None:
            return {}
        if isinstance(value, (dict, list)):
            return value
        if isinstance(value, (str, bytes)):
            return json.loads(value)
        if hasattr(value, "__dict__"):
            return dict(vars(value))
        raise TypeError(f"Cannot coax to array: {type(value).__name__}")

    def _throw_if_primary_key_misconfigured(self, row: Mapping[str, Any]) -> None:
        pk = self.primary_key_column_name
        if pk is None:
            return
        if pk not in row:
            raise CipherSweetException(
                "EncryptedRow is configured with a primary key name, so it must be pre-populated on inserts"
            )
        if pk in self.fields_to_encrypt:
            raise CipherSweetException("Primary key must not be encrypted")

    @staticmethod
    def _field_not_optional(field: str, type_: str) -> None:
        raise TypeError(
            f"Received a NULL value for {field}, which has a non-optional type. "
            f"To fix this, try changing the type declaration from {type_!r} to {'?' + type_!r}."
        )
