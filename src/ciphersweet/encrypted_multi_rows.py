"""``EncryptedMultiRows``: several ``EncryptedRow`` objects keyed by table name."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from . import constants as C
from .aad import AAD, AADLike
from .backend import Backend
from .blind_index import BlindIndex, CompoundIndex
from .encrypted_row import EncryptedRow, IndexValue
from .engine import CipherSweet
from .exceptions import CipherSweetException
from .json_field import JsonFieldMap

Rows = Dict[str, Dict[str, Any]]


class EncryptedMultiRows:
    """Encrypt related rows from several tables in one call."""

    def __init__(
        self, engine: CipherSweet, use_typed_indexes: bool = False, auto_bind_context: bool = False
    ) -> None:
        self.engine = engine
        self.typed_indexes = use_typed_indexes
        self.auto_bind_context = auto_bind_context
        self.tables: Dict[str, EncryptedRow] = {}
        self.permit_empty: Optional[bool] = None

    def add_table(self, table_name: str) -> EncryptedMultiRows:
        if table_name in self.tables:
            raise CipherSweetException("Table already exists")
        self.tables[table_name] = EncryptedRow(self.engine, table_name)
        return self

    def add_field(
        self, table_name: str, field_name: str, type_: str = C.TYPE_TEXT, aad_source: AADLike = ""
    ) -> EncryptedMultiRows:
        if self.auto_bind_context:
            source = aad_source if aad_source else AAD()
            aad_source = AAD.field(source).merge(AAD.literal(f"table={table_name};field={field_name}"))
        self.get_encrypted_row_object_for_table(table_name).add_field(
            field_name, type_, aad_source, self.auto_bind_context
        )
        return self

    def add_text_field(self, table: str, field: str, aad_source: AADLike = "") -> EncryptedMultiRows:
        return self.add_field(table, field, C.TYPE_TEXT, aad_source)

    def add_boolean_field(self, table: str, field: str, aad_source: AADLike = "") -> EncryptedMultiRows:
        return self.add_field(table, field, C.TYPE_BOOLEAN, aad_source)

    def add_float_field(self, table: str, field: str, aad_source: AADLike = "") -> EncryptedMultiRows:
        return self.add_field(table, field, C.TYPE_FLOAT, aad_source)

    def add_integer_field(self, table: str, field: str, aad_source: AADLike = "") -> EncryptedMultiRows:
        return self.add_field(table, field, C.TYPE_INT, aad_source)

    def add_optional_text_field(self, table: str, field: str, aad_source: AADLike = "") -> EncryptedMultiRows:
        return self.add_field(table, field, C.TYPE_OPTIONAL_TEXT, aad_source)

    def add_optional_boolean_field(
        self, table: str, field: str, aad_source: AADLike = ""
    ) -> EncryptedMultiRows:
        return self.add_field(table, field, C.TYPE_OPTIONAL_BOOLEAN, aad_source)

    def add_optional_float_field(
        self, table: str, field: str, aad_source: AADLike = ""
    ) -> EncryptedMultiRows:
        return self.add_field(table, field, C.TYPE_OPTIONAL_FLOAT, aad_source)

    def add_optional_integer_field(
        self, table: str, field: str, aad_source: AADLike = ""
    ) -> EncryptedMultiRows:
        return self.add_field(table, field, C.TYPE_OPTIONAL_INT, aad_source)

    def add_json_field(
        self, table: str, field: str, field_map: JsonFieldMap, aad_source: AADLike = "", strict: bool = True
    ) -> EncryptedMultiRows:
        self.get_encrypted_row_object_for_table(table).add_json_field(field, field_map, aad_source, strict)
        return self

    def add_optional_json_field(
        self, table: str, field: str, field_map: JsonFieldMap, aad_source: AADLike = "", strict: bool = True
    ) -> EncryptedMultiRows:
        self.get_encrypted_row_object_for_table(table).add_nullable_json_field(
            field, field_map, aad_source, strict
        )
        return self

    def add_blind_index(self, table: str, column: str, index: BlindIndex) -> EncryptedMultiRows:
        self.get_encrypted_row_object_for_table(table).add_blind_index(column, index)
        return self

    def add_compound_index(self, table: str, index: CompoundIndex) -> EncryptedMultiRows:
        self.get_encrypted_row_object_for_table(table).add_compound_index(index)
        return self

    def create_compound_index(
        self,
        table: str,
        name: str,
        columns: Optional[Iterable[str]] = None,
        filter_bits: int = 256,
        fast_hash: bool = False,
        hash_config: Optional[Mapping[str, Any]] = None,
    ) -> CompoundIndex:
        return self.get_encrypted_row_object_for_table(table).create_compound_index(
            name, columns, filter_bits, fast_hash, hash_config
        )

    def create_fast_compound_index(
        self,
        table: str,
        name: str,
        columns: Optional[Iterable[str]] = None,
        filter_bits: int = 256,
        hash_config: Optional[Mapping[str, Any]] = None,
    ) -> CompoundIndex:
        return self.get_encrypted_row_object_for_table(table).create_fast_compound_index(
            name, columns, filter_bits, hash_config
        )

    def decrypt_many_rows(self, rows: Mapping[str, Mapping[str, Any]]) -> Rows:
        out: Rows = {k: dict(v) if isinstance(v, Mapping) else v for k, v in rows.items()}
        for table in list(self.tables):
            if rows.get(table) is not None:
                out[table] = self.get_encrypted_row_object_for_table(table).decrypt_row(rows[table])
        return out

    def encrypt_many_rows(self, rows: Mapping[str, Mapping[str, Any]]) -> Rows:
        out: Rows = {k: dict(v) if isinstance(v, Mapping) else v for k, v in rows.items()}
        for table in list(self.tables):
            if rows.get(table) is not None:
                out[table] = self.get_encrypted_row_object_for_table(table).encrypt_row(rows[table])
        return out

    def get_blind_index(self, table: str, index_name: str, row: Mapping[str, Any]) -> IndexValue:
        return self.get_encrypted_row_object_for_table(table).get_blind_index(index_name, row)

    def get_blind_indexes_for_table(self, table: str, row: Mapping[str, Any]) -> Dict[str, IndexValue]:
        return self.get_encrypted_row_object_for_table(table).get_all_blind_indexes(row)

    def get_all_blind_indexes(
        self, rows: Mapping[str, Mapping[str, Any]]
    ) -> Dict[str, Dict[str, IndexValue]]:
        return {
            table: self.get_encrypted_row_object_for_table(table).get_all_blind_indexes(rows[table])
            for table in list(self.tables)
            if rows.get(table) is not None
        }

    def get_blind_index_type(self, table: str, column: str, name: str) -> str:
        return self.get_encrypted_row_object_for_table(table).get_blind_index_type(column, name)

    def get_compound_index_type(self, table: str, name: str) -> str:
        return self.get_encrypted_row_object_for_table(table).get_compound_index_type(name)

    def get_encrypted_row_object_for_table(self, table_name: str = "") -> EncryptedRow:
        if table_name not in self.tables:
            self.add_table(table_name)
        row = self.tables[table_name]
        row.set_typed_indexes(self.typed_indexes)
        if self.permit_empty is not None:
            row.set_permit_empty(self.permit_empty)
        return row

    def list_tables(self) -> List[str]:
        return list(self.tables)

    def set_auto_bind_context(self, value: bool = False) -> EncryptedMultiRows:
        self.auto_bind_context = value
        return self

    def set_primary_key_column_name(self, table: str, column: Optional[str]) -> EncryptedMultiRows:
        self.get_encrypted_row_object_for_table(table).set_primary_key_column_name(column)
        return self

    def set_aad_source_field(self, table: str, field: str, aad_source: AADLike) -> EncryptedMultiRows:
        self.get_encrypted_row_object_for_table(table).set_aad_source_field(field, aad_source)
        return self

    def set_permit_empty(self, permitted: bool) -> EncryptedMultiRows:
        self.permit_empty = permitted
        return self

    def prepare_for_storage(
        self, rows: Mapping[str, Mapping[str, Any]]
    ) -> Tuple[Rows, Dict[str, Dict[str, IndexValue]]]:
        tables: Rows = {}
        indexes: Dict[str, Dict[str, IndexValue]] = {}
        for table in list(self.tables):
            if rows.get(table) is not None:
                er = self.get_encrypted_row_object_for_table(table)
                tables[table] = er.encrypt_row(rows[table])
                indexes[table] = er.get_all_blind_indexes(rows[table])
        return tables, indexes

    def get_backend(self) -> Backend:
        return self.engine.get_backend()

    def get_engine(self) -> CipherSweet:
        return self.engine

    def get_flat_indexes(self) -> bool:
        return not self.typed_indexes

    def set_flat_indexes(self, flat: bool) -> EncryptedMultiRows:
        self.typed_indexes = not flat
        return self

    def get_typed_indexes(self) -> bool:
        return self.typed_indexes

    def set_typed_indexes(self, typed: bool) -> EncryptedMultiRows:
        self.typed_indexes = typed
        return self
