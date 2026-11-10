"""Low-level helpers that reproduce the exact byte-level behaviour of
``ParagonIE\\CipherSweet\\Util`` and the bits of PHP semantics CipherSweet
relies on (string coercion, ``sort()``, ``json_encode()``, ...).

Everything in here is internal. The public API lives in the other modules.
"""

from __future__ import annotations

import base64
import enum
import functools
import hashlib
import hmac
import json
import math
import re
import struct
from typing import Any, Iterable, List, Mapping, Optional, Sequence, Union

BytesLike = Union[bytes, bytearray, memoryview]
StrOrBytes = Union[str, bytes]


# ---------------------------------------------------------------------------
# Byte coercion
# ---------------------------------------------------------------------------


def to_bytes(value: Any) -> bytes:
    """Coerce *value* to bytes the way PHP's ``(string)`` cast would.

    ``str`` is UTF-8 encoded; everything else goes through :func:`php_strval`.
    """
    if isinstance(value, bytes):
        return value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8")
    return php_strval(value).encode("utf-8")


def php_float_to_string(value: float, precision: int = 14) -> str:
    """Render a float the way PHP's ``(string)$float`` does.

    PHP uses the ``precision`` ini setting (default 14 significant digits)
    and ``zend_gcvt`` formatting: exponential notation when the decimal
    exponent is below -4 or at least ``precision``.
    """
    if math.isnan(value):
        return "NAN"
    if math.isinf(value):
        return "INF" if value > 0 else "-INF"
    if value == 0.0:
        return "-0" if math.copysign(1.0, value) < 0 else "0"
    sign = "-" if value < 0 else ""
    mant, exp_s = f"{abs(value):.{precision - 1}e}".split("e")
    digits = mant.replace(".", "").rstrip("0") or "0"
    decpt = int(exp_s) + 1
    if (decpt < -3) if decpt < 0 else (decpt > precision):
        e = decpt - 1
        m = digits[0] + "." + (digits[1:] or "0")
        return f"{sign}{m}E{'+' if e >= 0 else '-'}{abs(e)}"
    if decpt <= 0:
        return sign + "0." + "0" * (-decpt) + digits
    if decpt >= len(digits):
        return sign + digits + "0" * (decpt - len(digits))
    return sign + digits[:decpt] + "." + digits[decpt:]


def php_strval(value: Any) -> str:
    """Return the PHP ``(string)`` representation of a scalar."""
    if value is None:
        return ""
    if value is True:
        return "1"
    if value is False:
        return ""
    if isinstance(value, enum.Enum):
        return php_strval(enum_to_scalar(value))
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return php_float_to_string(value)
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).decode("utf-8", errors="surrogateescape")
    raise TypeError(f"Cannot convert {type(value).__name__} to string")


def php_empty(value: Any) -> bool:
    """PHP ``empty()`` for scalars."""
    if value is None or value is False:
        return True
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value == 0
    if isinstance(value, (str, bytes)):
        return len(value) == 0 or value in ("0", b"0")
    if isinstance(value, (list, tuple, dict)):
        return len(value) == 0
    return False


def enum_to_scalar(value: enum.Enum) -> Any:
    """Mirror ``EncryptedRow::enumToScalar``: backed enums give their value,
    pure enums give their name."""
    if isinstance(value.value, (str, int)):
        return value.value
    return value.name


# ---------------------------------------------------------------------------
# Encodings
# ---------------------------------------------------------------------------


def b64url_encode(data: bytes) -> str:
    """``ParagonIE\\ConstantTime\\Base64UrlSafe::encode`` (padded)."""
    return base64.urlsafe_b64encode(data).decode("ascii")


_B64URL_RE = re.compile(rb"^[A-Za-z0-9_-]*$")


def b64url_decode(data: StrOrBytes) -> bytes:
    """``Base64UrlSafe::decode`` - padding is optional."""
    if isinstance(data, str):
        data = data.encode("ascii")
    data = data.rstrip(b"=")
    if not _B64URL_RE.match(data) or len(data) % 4 == 1:
        raise ValueError("Invalid base64url string")
    return base64.urlsafe_b64decode(data + b"=" * (-len(data) % 4))


def base32_encode_unpadded(data: bytes) -> str:
    """``ParagonIE\\ConstantTime\\Base32::encodeUnpadded`` (lowercase RFC 4648)."""
    return base64.b32encode(data).decode("ascii").rstrip("=").lower()


def hex_encode(data: bytes) -> str:
    return data.hex()


# ---------------------------------------------------------------------------
# Integer packing
# ---------------------------------------------------------------------------


def store32_le(n: int) -> bytes:
    return struct.pack("<I", n & 0xFFFFFFFF)


def store64_le(n: int) -> bytes:
    return struct.pack("<Q", n & 0xFFFFFFFFFFFFFFFF)


def pack(pieces: Sequence[StrOrBytes]) -> bytes:
    """``Util::pack``: LE32(count) || (LE64(len) || piece)*"""
    out = [store32_le(len(pieces))]
    for piece in pieces:
        b = to_bytes(piece)
        out.append(store64_le(len(b)))
        out.append(b)
    return b"".join(out)


def and_mask(data: bytes, bits: int, bitwise_left: bool = False) -> bytes:
    """``Util::andMask`` - truncate *data* to *bits* bits."""
    nbytes = bits >> 3
    if nbytes >= len(data):
        data = data + b"\x00" * ((nbytes - len(data)) + 1)
    out = data[:nbytes]
    left_over = bits - (nbytes << 3)
    if left_over > 0:
        mask = (1 << left_over) - 1
        if not bitwise_left:
            mask = ((mask & 0xF0) >> 4) | ((mask & 0x0F) << 4)
            mask = ((mask & 0xCC) >> 2) | ((mask & 0x33) << 2)
            mask = ((mask & 0xAA) >> 1) | ((mask & 0x55) << 1)
        out += bytes([data[nbytes] & mask])
    return out


def bool_to_chr(value: Optional[bool]) -> bytes:
    if value is None:
        return b"\x00"
    return b"\x02" if value else b"\x01"


def chr_to_bool(data: bytes) -> Optional[bool]:
    if len(data) != 1:
        raise ValueError("String is not 1 length long")
    v = data[0]
    if v == 0:
        return None
    if v == 1:
        return False
    if v == 2:
        return True
    raise ValueError("Internal integer is not 0, 1, or 2")


def int_to_string(value: int) -> bytes:
    return struct.pack("<q", value)


def string_to_int(data: bytes) -> int:
    if len(data) != 8:
        raise ValueError("Integer ciphertext must decrypt to 8 bytes")
    return struct.unpack("<q", data)[0]


def float_to_string(value: float) -> bytes:
    return struct.pack("<d", value)


def string_to_float(data: bytes) -> float:
    if len(data) != 8:
        raise ValueError("Float ciphertext must decrypt to 8 bytes")
    return struct.unpack("<d", data)[0]


def ctr_nonce_increase(nonce: bytes, amount: int = 1) -> bytes:
    """``Util::ctrNonceIncrease`` - big-endian 128-bit add."""
    n = (int.from_bytes(nonce, "big") + amount) % (1 << 128)
    return n.to_bytes(16, "big")


# ---------------------------------------------------------------------------
# Primitive crypto
# ---------------------------------------------------------------------------


def hkdf(
    key: bytes,
    salt: Optional[bytes] = b"",
    info: bytes = b"",
    length: int = 32,
    hash_name: str = "sha384",
) -> bytes:
    """PHP ``hash_hkdf($hash, $key, $length, $info, $salt)`` (RFC 5869)."""
    hash_len = hashlib.new(hash_name).digest_size
    if not salt:
        salt = b"\x00" * hash_len
    prk = hmac.new(salt, key, hash_name).digest()
    okm = b""
    t = b""
    i = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hash_name).digest()
        okm += t
        i += 1
    return okm[:length]


def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, "sha256").digest()


def hmac_sha384(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, "sha384").digest()


def generichash(message: bytes, key: bytes = b"", length: int = 32) -> bytes:
    """libsodium ``crypto_generichash`` (BLAKE2b, optionally keyed)."""
    return hashlib.blake2b(message, digest_size=length, key=key).digest()


def hash_equals(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


# ---------------------------------------------------------------------------
# CRC32C (Castagnoli), as used by JsonFieldMap
# ---------------------------------------------------------------------------


@functools.lru_cache(maxsize=1)
def _crc32c_table() -> List[int]:
    table = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ 0x82F63B78 if c & 1 else c >> 1
        table.append(c)
    return table


def crc32c_hex(data: bytes) -> str:
    """PHP ``hash('crc32c', $data)``."""
    table = _crc32c_table()
    crc = 0xFFFFFFFF
    for b in data:
        crc = table[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return f"{crc ^ 0xFFFFFFFF:08x}"


# ---------------------------------------------------------------------------
# PHP sort() with SORT_REGULAR on strings (PHP 8 comparison semantics)
# ---------------------------------------------------------------------------

_NUMERIC_RE = re.compile(r"^[ \t\n\r\v\f]*[+-]?(\d+(\.\d*)?|\.\d+)([eE][+-]?\d+)?[ \t\n\r\v\f]*$")


def _is_numeric(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, (int, float)):
        return True
    if isinstance(value, bytes):
        try:
            value = value.decode("ascii")
        except UnicodeDecodeError:
            return False
    return isinstance(value, str) and bool(_NUMERIC_RE.match(value))


def _php_compare(a: Any, b: Any) -> int:
    if _is_numeric(a) and _is_numeric(b):
        fa, fb = float(a), float(b)
        return (fa > fb) - (fa < fb)
    ba, bb = to_bytes(a), to_bytes(b)
    return (ba > bb) - (ba < bb)


def php_sort(values: Iterable[Any]) -> List[Any]:
    """Sort like PHP's ``sort($array)`` (numeric strings compare numerically)."""
    return sorted(values, key=functools.cmp_to_key(_php_compare))


# ---------------------------------------------------------------------------
# PHP json_encode() (default flags)
# ---------------------------------------------------------------------------

_INT_KEY_RE = re.compile(r"^(0|-?[1-9][0-9]*)$")


def _php_array_is_list(obj: Mapping[Any, Any]) -> bool:
    expected = 0
    for k in obj.keys():
        if isinstance(k, bool):
            return False
        if isinstance(k, int):
            ki = k
        elif isinstance(k, str) and _INT_KEY_RE.match(k):
            ki = int(k)
        else:
            return False
        if ki != expected:
            return False
        expected += 1
    return True


def _php_jsonable(obj: Any) -> Any:
    if isinstance(obj, Mapping):
        if _php_array_is_list(obj):
            return [_php_jsonable(v) for v in obj.values()]
        return {php_strval(k): _php_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_php_jsonable(v) for v in obj]
    if isinstance(obj, (bytes, bytearray, memoryview)):
        return bytes(obj).decode("utf-8")
    if isinstance(obj, enum.Enum):
        return enum_to_scalar(obj)
    return obj


def php_json_encode(obj: Any) -> str:
    """Approximate ``json_encode($obj)`` with PHP's default flags:
    compact separators, ``\\uXXXX`` escapes for non-ASCII and escaped ``/``."""
    data = _php_jsonable(obj)
    encoded = json.dumps(data, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
    return encoded.replace("/", "\\/")
