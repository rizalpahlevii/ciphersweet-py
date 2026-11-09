"""Additional authenticated data (``ParagonIE\\CipherSweet\\AAD``)."""

from __future__ import annotations

import copy
from typing import Any, Iterable, List, Mapping, Optional, Union

from ._util import php_sort, store64_le, to_bytes


class AAD:
    """Binds a ciphertext to other values (other columns or literals).

    ``AAD.field("id")`` and ``AAD.literal("x")`` reproduce PHP's legacy
    single-value behaviour; combining several values (via the constructor or
    :meth:`merge`) uses the canonical length-prefixed encoding.
    """

    def __init__(
        self,
        field_names: Optional[Iterable[str]] = None,
        literals: Optional[Iterable[Any]] = None,
        legacy: bool = False,
    ) -> None:
        self.field_names: List[str] = list(field_names or [])
        self.literals: List[Any] = list(literals or [])
        self.legacy = legacy

    def add_field_name(self, field_name: str) -> AAD:
        if field_name not in self.field_names:
            self.field_names.append(field_name)
        return self

    def add_literal(self, literal: Any) -> AAD:
        if literal not in self.literals:
            self.literals.append(literal)
        return self

    def canonicalize(self, plaintext_row: Optional[Mapping[str, Any]] = None) -> bytes:
        row = plaintext_row or {}
        if self.legacy:
            if not self.field_names and not self.literals:
                return b""
            if len(self.field_names) == 1:
                return to_bytes(row[self.field_names[0]])
            if len(self.literals) == 1:
                return to_bytes(self.literals[0])
        self.field_names = php_sort(self.field_names)
        self.literals = php_sort(self.literals)
        out = [
            store64_le(len(self.field_names) + len(self.literals)),
            store64_le(len(self.field_names)),
            store64_le(len(self.literals)),
        ]
        for name in self.field_names:
            nb = to_bytes(name)
            value = row.get(name)
            vb = to_bytes(value) if value is not None else b""
            out += [store64_le(len(nb)), nb, store64_le(len(vb)), vb]
        for literal in self.literals:
            lb = to_bytes(literal)
            out += [store64_le(len(lb)), lb]
        return b"".join(out)

    def get_collapsed(self, row: Mapping[str, Any]) -> AAD:
        clone = AAD([], list(self.literals))
        for name in php_sort(self.field_names):
            if name in row:
                clone.add_literal(to_bytes(row[name]).decode("utf-8", "surrogateescape"))
        clone.literals = php_sort(clone.literals)
        return clone

    def get_field_names(self) -> List[str]:
        return self.field_names

    def get_literals(self) -> List[Any]:
        return self.literals

    def get_legacy(self) -> bool:
        return self.legacy

    def merge(self, other: AAD) -> AAD:
        merged = copy.deepcopy(self)
        for name in other.field_names:
            if name not in merged.field_names:
                merged.field_names.append(name)
        for literal in other.literals:
            if literal not in merged.literals:
                merged.literals.append(literal)
        merged.legacy = False
        return merged

    @staticmethod
    def field(value: Union[str, bytes, AAD, None]) -> AAD:
        if isinstance(value, AAD):
            return copy.deepcopy(value)
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        if not value:
            return AAD([], [], True)
        return AAD([value], [], True)

    @staticmethod
    def literal(value: Union[str, bytes, AAD, None]) -> AAD:
        if isinstance(value, AAD):
            return copy.deepcopy(value)
        if not value or value in ("0", b"0"):
            # PHP empty("0") is true
            return AAD([], [], True)
        return AAD([], [value], True)

    def __repr__(self) -> str:
        return f"AAD(field_names={self.field_names!r}, literals={self.literals!r}, legacy={self.legacy})"


AADLike = Union[str, bytes, AAD, None]
