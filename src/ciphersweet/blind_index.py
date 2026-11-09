"""Blind index definitions (``BlindIndex``, ``CompoundIndex`` and the fast variants)."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, Optional

from ._util import to_bytes
from .exceptions import CipherSweetException
from .transformation import Compound, RowTransformation, Transformation


class BlindIndex:
    """A blind index over one field.

    Note that, like PHP, the default is a *slow* index (Argon2id for
    ``nacl``/``brng``, PBKDF2 for ``fips``). Pass ``fast_hash=True`` or use
    :class:`FastBlindIndex` for the BLAKE2b/PBKDF2-1 variant.

    :param name: index name; it is part of the key derivation.
    :param transformations: callables applied in order before hashing.
    :param filter_bits: output size in bits.
    :param fast_hash: use the fast hash.
    :param hash_config: slow hash tuning (``opslimit``/``memlimit`` or
        ``iterations`` for FIPS). Values below the defaults are ignored.
    """

    def __init__(
        self,
        name: str,
        transformations: Optional[Iterable[Transformation]] = None,
        filter_bits: int = 256,
        fast_hash: bool = False,
        hash_config: Optional[Mapping[str, Any]] = None,
    ) -> None:
        self.name = name
        self.transformations: List[Transformation] = list(transformations or [])
        self.filter_bits = filter_bits
        self.fast_hash = fast_hash
        self.hash_config: Dict[str, Any] = dict(hash_config or {})

    def add_transformation(self, tf: Transformation) -> BlindIndex:
        self.transformations.append(tf)
        return self

    def get_name(self) -> str:
        return self.name

    def get_fast_hash(self) -> bool:
        return self.fast_hash

    def get_hash_config(self) -> Dict[str, Any]:
        return self.hash_config

    def get_filter_bit_length(self) -> int:
        return self.filter_bits

    def get_transformed(self, value: Any) -> bytes:
        output: Any = value
        for tf in self.transformations:
            output = tf(output)
        return to_bytes(output)

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}({self.name!r}, filter_bits={self.filter_bits}, "
            f"fast_hash={self.fast_hash})"
        )


class FastBlindIndex(BlindIndex):
    """A :class:`BlindIndex` that always uses the fast hash."""

    def __init__(
        self,
        name: str,
        transformations: Optional[Iterable[Transformation]] = None,
        filter_bits: int = 256,
        fast_hash: bool = True,
        hash_config: Optional[Mapping[str, Any]] = None,
    ) -> None:
        if not fast_hash:
            raise CipherSweetException("FastBlindIndex cannot be turned slow")
        super().__init__(name, transformations, filter_bits, True, hash_config)


class CompoundIndex:
    """A blind index computed over several columns of a row."""

    _compounder = Compound()

    def __init__(
        self,
        name: str,
        columns: Optional[Iterable[str]] = None,
        filter_bits: int = 256,
        fast_hash: bool = False,
        hash_config: Optional[Mapping[str, Any]] = None,
    ) -> None:
        self.name = name
        self.columns: List[str] = list(columns or [])
        self.filter_bits = filter_bits
        self.fast_hash = fast_hash
        self.hash_config: Dict[str, Any] = dict(hash_config or {})
        self.column_transforms: Dict[str, List[Transformation]] = {}
        self.row_transforms: List[RowTransformation] = []

    def add_transform(self, column: str, tf: Transformation) -> CompoundIndex:
        self.column_transforms.setdefault(column, []).append(tf)
        return self

    def add_row_transform(self, tf: RowTransformation) -> CompoundIndex:
        self.row_transforms.append(tf)
        return self

    def get_columns(self) -> List[str]:
        return self.columns

    def get_name(self) -> str:
        return self.name

    def get_fast_hash(self) -> bool:
        return self.fast_hash

    def get_filter_bit_length(self) -> int:
        return self.filter_bits

    def get_hash_config(self) -> Dict[str, Any]:
        return self.hash_config

    def get_transforms(self, column: str) -> List[Transformation]:
        return self.column_transforms.get(column, [])

    def get_row_transforms(self) -> List[RowTransformation]:
        return self.row_transforms

    def get_packed(self, row: Mapping[str, Any]) -> bytes:
        pieces: Any = {}
        for col in self.columns:
            if col not in row:
                continue
            piece = row[col]
            for tf in self.column_transforms.get(col, []):
                piece = tf(piece)
            pieces[col] = piece
        for rtf in self.row_transforms:
            pieces = rtf(pieces)
        if isinstance(pieces, (str, bytes)):
            return to_bytes(pieces)
        return self._compounder(pieces)

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}({self.name!r}, columns={self.columns!r}, "
            f"filter_bits={self.filter_bits}, fast_hash={self.fast_hash})"
        )


class FastCompoundIndex(CompoundIndex):
    """A :class:`CompoundIndex` that always uses the fast hash."""

    def __init__(
        self,
        name: str,
        columns: Optional[Iterable[str]] = None,
        filter_bits: int = 256,
        fast_hash: bool = True,
        hash_config: Optional[Mapping[str, Any]] = None,
    ) -> None:
        if not fast_hash:
            raise CipherSweetException("FastCompoundIndex cannot be turned slow")
        super().__init__(name, columns, filter_bits, True, hash_config)
