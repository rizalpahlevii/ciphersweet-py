"""DDL helpers for encrypted columns and blind index columns
(a port of ciphersweet-go's ``migrate`` package).

Ciphertexts are base64url text, so ``TEXT`` columns work everywhere. A blind
index of ``n`` bits is stored as ``ceil(n / 8) * 2`` hex characters.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List

_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class Dialect(Enum):
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    SQLITE = "sqlite"


def index_width(bits: int) -> int:
    """Hex characters needed for a blind index of ``bits`` bits."""
    return ((bits + 7) // 8) * 2


def _check(name: str) -> str:
    if not _IDENT.match(name):
        raise ValueError(f"Unsafe SQL identifier: {name!r}")
    return name


@dataclass
class _Column:
    name: str
    kind: str  # "encrypted" | "index"
    length: int = 0


@dataclass
class Plan:
    """Builds ``ALTER TABLE``/``CREATE TABLE`` statements.

    >>> Plan("users", Dialect.POSTGRESQL).add_encrypted_column("email").add_index_column("email_idx", 32).up()
    """

    table: str
    dialect: Dialect = Dialect.MYSQL
    columns: List[_Column] = field(default_factory=list)

    def __post_init__(self) -> None:
        _check(self.table)

    def add_encrypted_column(self, name: str) -> Plan:
        self.columns.append(_Column(_check(name), "encrypted"))
        return self

    def add_index_column(self, name: str, bits: int = 256) -> Plan:
        self.columns.append(_Column(_check(name), "index", index_width(bits)))
        return self

    def _q(self, name: str) -> str:
        return f"`{name}`" if self.dialect is Dialect.MYSQL else f'"{name}"'

    def _idx_name(self, col: str) -> str:
        return f"idx_{self.table}_{col}"

    def _col_type(self, col: _Column) -> str:
        return "TEXT" if col.kind == "encrypted" else f"VARCHAR({col.length})"

    def _create_index(self, col: str) -> str:
        return f"CREATE INDEX {self._q(self._idx_name(col))} ON {self._q(self.table)} ({self._q(col)});\n"

    def _drop_index(self, col: str) -> str:
        if self.dialect is Dialect.MYSQL:
            return f"DROP INDEX {self._q(self._idx_name(col))} ON {self._q(self.table)};\n"
        return f"DROP INDEX IF EXISTS {self._q(self._idx_name(col))};\n"

    def up(self) -> str:
        out = []
        for col in self.columns:
            out.append(
                f"ALTER TABLE {self._q(self.table)} ADD COLUMN {self._q(col.name)} {self._col_type(col)} NULL;\n"
            )
            if col.kind == "index":
                out.append(self._create_index(col.name))
        return "".join(out)

    def down(self) -> str:
        out = []
        for col in reversed(self.columns):
            if col.kind == "index":
                out.append(self._drop_index(col.name))
            out.append(f"ALTER TABLE {self._q(self.table)} DROP COLUMN {self._q(col.name)};\n")
        return "".join(out)

    def create_table(self) -> str:
        if self.dialect is Dialect.POSTGRESQL:
            pk = "id BIGSERIAL PRIMARY KEY"
        elif self.dialect is Dialect.SQLITE:
            pk = "id INTEGER PRIMARY KEY AUTOINCREMENT"
        else:
            pk = "id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY"
        lines = [pk] + [f"{self._q(c.name)} {self._col_type(c)} NULL" for c in self.columns]
        body = ",\n    ".join(lines)
        out = [f"CREATE TABLE IF NOT EXISTS {self._q(self.table)} (\n    {body}\n);\n"]
        out += [self._create_index(c.name) for c in self.columns if c.kind == "index"]
        return "".join(out)


def laravel_blind_indexes_table(dialect: Dialect = Dialect.MYSQL) -> str:
    """DDL equivalent to spatie/laravel-ciphersweet's ``blind_indexes`` migration."""
    q = (lambda n: f"`{n}`") if dialect is Dialect.MYSQL else (lambda n: f'"{n}"')
    id_type = "BIGINT UNSIGNED" if dialect is Dialect.MYSQL else "BIGINT"
    return (
        f"CREATE TABLE IF NOT EXISTS {q('blind_indexes')} (\n"
        f"    {q('indexable_type')} VARCHAR(255) NOT NULL,\n"
        f"    {q('indexable_id')} {id_type} NOT NULL,\n"
        f"    {q('name')} VARCHAR(255) NOT NULL,\n"
        f"    {q('value')} VARCHAR(255) NOT NULL\n"
        ");\n"
        f"CREATE INDEX {q('blind_indexes_indexable_type_indexable_id_index')} "
        f"ON {q('blind_indexes')} ({q('indexable_type')}, {q('indexable_id')});\n"
        f"CREATE INDEX {q('blind_indexes_name_value_index')} ON {q('blind_indexes')} ({q('name')}, {q('value')});\n"
        f"CREATE UNIQUE INDEX {q('blind_indexes_indexable_type_indexable_id_name_unique')} "
        f"ON {q('blind_indexes')} ({q('indexable_type')}, {q('indexable_id')}, {q('name')});\n"
    )
