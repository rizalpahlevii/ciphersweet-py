"""XChaCha20 stream cipher (libsodium ``crypto_stream_xchacha20_xor``).

PyNaCl does not expose the raw XChaCha20 stream, so we derive the HChaCha20
sub-key here and hand the actual keystream work to ``cryptography``'s
ChaCha20 implementation.
"""

from __future__ import annotations

import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

_SIGMA = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)
_MASK = 0xFFFFFFFF


def _rotl(v: int, c: int) -> int:
    return ((v << c) & _MASK) | (v >> (32 - c))


def _quarter(s: list, a: int, b: int, c: int, d: int) -> None:
    s[a] = (s[a] + s[b]) & _MASK
    s[d] = _rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & _MASK
    s[b] = _rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & _MASK
    s[d] = _rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & _MASK
    s[b] = _rotl(s[b] ^ s[c], 7)


def hchacha20(key: bytes, nonce16: bytes) -> bytes:
    if len(key) != 32 or len(nonce16) != 16:
        raise ValueError("HChaCha20 needs a 32-byte key and a 16-byte nonce")
    s = list(_SIGMA) + list(struct.unpack("<8I", key)) + list(struct.unpack("<4I", nonce16))
    for _ in range(10):
        _quarter(s, 0, 4, 8, 12)
        _quarter(s, 1, 5, 9, 13)
        _quarter(s, 2, 6, 10, 14)
        _quarter(s, 3, 7, 11, 15)
        _quarter(s, 0, 5, 10, 15)
        _quarter(s, 1, 6, 11, 12)
        _quarter(s, 2, 7, 8, 13)
        _quarter(s, 3, 4, 9, 14)
    return struct.pack("<8I", *(s[0:4] + s[12:16]))


def xchacha20_xor(message: bytes, nonce: bytes, key: bytes) -> bytes:
    """Equivalent to ``sodium_crypto_stream_xchacha20_xor``."""
    if len(nonce) != 24:
        raise ValueError("XChaCha20 nonce must be 24 bytes")
    subkey = hchacha20(key, nonce[:16])
    # libsodium uses the original ChaCha20 (64-bit counter, 64-bit nonce)
    # starting at block 0. With OpenSSL's 16-byte IV layout
    # (LE32 counter || 96-bit nonce) that is: 0x00*8 || nonce[16:24].
    iv = b"\x00" * 8 + nonce[16:24]
    enc = Cipher(algorithms.ChaCha20(subkey, iv), mode=None).encryptor()
    return enc.update(message) + enc.finalize()
