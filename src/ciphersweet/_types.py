"""``TypeEncodingTrait``: how typed values are turned into plaintext bytes."""

from __future__ import annotations

import enum
from typing import Any, Union

from . import constants as C
from ._util import (
    bool_to_chr,
    chr_to_bool,
    enum_to_scalar,
    float_to_string,
    int_to_string,
    php_empty,
    string_to_float,
    string_to_int,
    to_bytes,
)


def convert_to_bytes(data: Any, type_: str) -> bytes:
    if isinstance(data, enum.Enum):
        data = enum_to_scalar(data)
    if type_ in (C.TYPE_OPTIONAL_BOOLEAN, C.TYPE_BOOLEAN):
        if data is not None and not isinstance(data, bool):
            data = not php_empty(data)
        return bool_to_chr(data)
    if type_ in (C.TYPE_OPTIONAL_FLOAT, C.TYPE_FLOAT):
        if isinstance(data, bool) or not isinstance(data, (int, float)):
            raise TypeError("Expected a float")
        return float_to_string(float(data))
    if type_ in (C.TYPE_OPTIONAL_INT, C.TYPE_INT):
        if isinstance(data, bool) or not isinstance(data, int):
            raise TypeError("Expected an integer")
        return int_to_string(data)
    return to_bytes(data)


def decode_text(data: bytes) -> Union[str, bytes]:
    """UTF-8 decode, falling back to raw bytes for binary plaintexts."""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data


def convert_from_bytes(data: bytes, type_: str) -> Any:
    if type_ in (C.TYPE_OPTIONAL_BOOLEAN, C.TYPE_BOOLEAN):
        return chr_to_bool(data)
    if type_ in (C.TYPE_OPTIONAL_FLOAT, C.TYPE_FLOAT):
        return string_to_float(data)
    if type_ in (C.TYPE_OPTIONAL_INT, C.TYPE_INT):
        return string_to_int(data)
    return decode_text(data)
