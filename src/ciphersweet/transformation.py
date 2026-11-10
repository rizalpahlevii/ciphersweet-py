"""Blind index transformations (``ParagonIE\\CipherSweet\\Transformation``).

A transformation is any callable taking one value and returning ``bytes``
(or ``str``). The built-ins operate on bytes so the output is identical to
PHP, including for non-ASCII input (PHP strings are byte strings and
``strtolower`` is ASCII-only).
"""

from __future__ import annotations

import enum
import re
from typing import Any, Callable, Dict, List, Mapping, Union

from ._util import b64url_encode, php_float_to_string, store64_le, to_bytes

Transformation = Callable[[Any], Union[bytes, str]]
RowTransformation = Callable[[Dict[str, Any]], Union[Dict[str, Any], bytes, str]]


class Lowercase:
    """``strtolower`` (ASCII only, as in PHP 8.2+)."""

    def __call__(self, value: Any) -> bytes:
        return to_bytes(value).lower()


class AlphaCharactersOnly:
    """Strip everything except ``A-Z`` and ``a-z``."""

    def __call__(self, value: Any) -> bytes:
        return re.sub(rb"[^A-Za-z]", b"", to_bytes(value))


class AlphaNumericCharactersOnly:
    """Strip everything except ASCII letters and digits."""

    def __call__(self, value: Any) -> bytes:
        return re.sub(rb"[^a-zA-Z0-9]", b"", to_bytes(value))


class DigitsOnly:
    """Strip everything except ``0-9``."""

    def __call__(self, value: Any) -> bytes:
        return re.sub(rb"[^0-9]", b"", to_bytes(value))


class FirstCharacter:
    """The first *byte* of the input (PHP ``$input[0]``)."""

    def __call__(self, value: Any) -> bytes:
        return to_bytes(value)[:1]


class LastFourDigits:
    """The last four digits, left-padded with ``0``."""

    def __call__(self, value: Any) -> bytes:
        digits = re.sub(rb"[^0-9]", b"", to_bytes(value))
        return digits.rjust(4, b"0")[-4:]


class Compound:
    """The default row transformation for compound indexes: JSON-encodes the
    row with every string replaced by ``hex(LE64(len)) || base64url(str)``."""

    def __call__(self, value: Any) -> bytes:
        from ._util import php_json_encode

        if not isinstance(value, Mapping) and not isinstance(value, (list, tuple)):
            raise TypeError("Compound Transformation expects an array")
        return php_json_encode(self.process_array(value)).encode("ascii")

    @staticmethod
    def pack_string(value: Union[str, bytes]) -> str:
        data = to_bytes(value)
        return store64_le(len(data)).hex() + b64url_encode(data)

    def process_array(self, value: Any, layer: int = 0) -> Any:
        if layer > 255:
            raise RecursionError("Too much recursion")
        items = value.items() if isinstance(value, Mapping) else enumerate(value)
        out: Dict[Any, Any] = {}
        for key, item in items:
            if isinstance(item, enum.Enum):
                from ._util import enum_to_scalar

                item = enum_to_scalar(item)
            if isinstance(item, (Mapping, list, tuple)):
                out[key] = self.process_array(item, layer + 1)
            elif isinstance(item, float):
                out[key] = self.pack_string(php_float_to_string(item))
            elif isinstance(item, (str, bytes, bytearray)):
                out[key] = self.pack_string(bytes(item) if not isinstance(item, str) else item)
            else:
                out[key] = item
        return out


__all__: List[str] = [
    "AlphaCharactersOnly",
    "AlphaNumericCharactersOnly",
    "Compound",
    "DigitsOnly",
    "FirstCharacter",
    "LastFourDigits",
    "Lowercase",
    "RowTransformation",
    "Transformation",
]
