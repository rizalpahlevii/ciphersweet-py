"""
Utility functions for CipherSweet:
- ciphersweet_pack(): multi-part message packing (anti-canonicalization)
- hkdf_sha384(): HKDF with SHA-384 (used by FIPSCrypto key derivation)
- derive_field_key(): derives per-field encryption key from master key
"""

import struct
import hmac
import hashlib
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography.hazmat.primitives import hashes


def le32(n: int) -> bytes:
    """Encode n as a 4-byte little-endian unsigned int with MSB cleared."""
    n = n & 0x7FFFFFFF
    return struct.pack("<I", n)


def le64(n: int) -> bytes:
    """Encode n as an 8-byte little-endian unsigned int with MSB cleared."""
    n = n & 0x7FFFFFFFFFFFFFFF
    return struct.pack("<Q", n)


def ciphersweet_pack(pieces: list) -> bytes:
    """
    CipherSweet multi-part message packing.
    Prefixes piece count (LE32) then length+data (LE64 each) for each piece.
    """
    count = len(pieces)
    out = le32(count)
    for piece in pieces:
        if isinstance(piece, str):
            piece = piece.encode("utf-8")
        out += le64(len(piece))
        out += piece
    return out


def hkdf_sha384(key: bytes, length: int, info: bytes, salt: bytes = b"") -> bytes:
    """HKDF using SHA-384."""
    h = HKDF(
        algorithm=hashes.SHA384(),
        length=length,
        salt=salt if salt else None,
        info=info,
    )
    return h.derive(key)


def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


# Domain separation constants (as per CipherSweet key hierarchy)
_C1 = bytes([0xB4] * 32)  # for field encryption key
_C2 = bytes([0x7E] * 32)  # for index root key


def derive_field_enc_key(master_key: bytes, table: str, field: str) -> bytes:
    """
    Derive the field encryption key from the master key.

    CipherSweet key hierarchy:
      field_enc_key = HKDF-SHA384(master_key, salt=table, info=(C1 || field), len=32)
    """
    info = _C1 + field.encode("utf-8")
    return hkdf_sha384(master_key, 32, info=info, salt=table.encode("utf-8"))


def derive_index_root_key(master_key: bytes, table: str, field: str) -> bytes:
    """
    Derive the index root key from the master key.

      index_root_key = HKDF-SHA384(master_key, salt=table, info=(C2 || field), len=32)
    """
    info = _C2 + field.encode("utf-8")
    return hkdf_sha384(master_key, 32, info=info, salt=table.encode("utf-8"))


def derive_blind_index_key(
    index_root_key: bytes, table: str, field: str, index_name: str
) -> bytes:
    """
    Derive a specific blind-index key:
      HMAC-SHA256(index_root_key, pack([table, field, index_name]))[:32]
    """
    msg = ciphersweet_pack([table.encode(), field.encode(), index_name.encode()])
    return hmac_sha256(index_root_key, msg)[:32]

