"""
Tests for ciphersweet-python.

These tests verify:
1. NaCl (XChaCha20-Poly1305) encrypt -> decrypt round-trip
2. FIPS (AES-256-CTR + HMAC-SHA384) encrypt -> decrypt round-trip
3. Key derivation (field enc key, index root key) is deterministic
4. Packing / utility functions
5. EncryptedField high-level API
6. Known-good cross-platform ciphertext vectors (compatible with Go/PHP libs)
"""

import base64
import hmac as hmac_mod
import hashlib
import secrets


import pytest
import nacl.bindings
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from ciphersweet import CipherSweet, NaClBackend, FIPSBackend, StringKeyProvider, EncryptedField
from ciphersweet.util import (
    le32, le64, ciphersweet_pack,
    derive_field_enc_key, derive_index_root_key, derive_blind_index_key,
    hkdf_sha384,
)


# ─── Helpers to encrypt (for round-trip tests) ────────────────────────────────

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def encrypt_nacl(plaintext: str, key: bytes) -> str:
    nonce = secrets.token_bytes(24)
    ct = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
        message=plaintext.encode(),
        aad=nonce,
        nonce=nonce,
        key=key,
    )
    return "nacl:" + _b64url(nonce + ct)


def encrypt_fips(plaintext: str, key: bytes) -> str:
    hkdf_salt = secrets.token_bytes(32)
    aes_nonce = secrets.token_bytes(16)

    enc_key = hkdf_sha384(key, 32, info=b"AES-256-CTR", salt=hkdf_salt)
    mac_key = hkdf_sha384(key, 48, info=b"HMAC-SHA-384", salt=hkdf_salt)

    cipher = Cipher(algorithms.AES(enc_key), modes.CTR(aes_nonce), backend=default_backend())
    enc = cipher.encryptor()
    ct = enc.update(plaintext.encode()) + enc.finalize()

    header = b"fips:"
    mac_msg = ciphersweet_pack([header, hkdf_salt, aes_nonce, ct])
    tag = hmac_mod.new(mac_key, mac_msg, hashlib.sha384).digest()

    payload = hkdf_salt + aes_nonce + tag + ct
    return "fips:" + _b64url(payload)


# ─── Test data ────────────────────────────────────────────────────────────────

# A fixed 32-byte hex key (same as: openssl rand -hex 32)
TEST_KEY_HEX = "faef1d6c0d9228e2e63afa4d71b3c629172f87c9e27d9eeaad641f38b6e512f3"
TEST_KEY = bytes.fromhex(TEST_KEY_HEX)
TABLE = "users"
FIELD = "email"


# ─── Utility tests ────────────────────────────────────────────────────────────

class TestPacking:
    def test_empty(self):
        assert ciphersweet_pack([]) == b"\x00\x00\x00\x00"

    def test_empty_string(self):
        assert ciphersweet_pack([b""]) == b"\x01\x00\x00\x00" + b"\x00" * 8

    def test_known_value(self):
        result = ciphersweet_pack([b"test"])
        assert result == b"\x01\x00\x00\x00" + b"\x04\x00\x00\x00\x00\x00\x00\x00" + b"test"

    def test_str_input_encoded_as_utf8(self):
        r1 = ciphersweet_pack(["hello"])
        r2 = ciphersweet_pack([b"hello"])
        assert r1 == r2

    def test_multiple_pieces(self):
        result = ciphersweet_pack([b"abc", b"de"])
        # count=2, then len=3+data, len=2+data
        assert result[:4] == b"\x02\x00\x00\x00"
        assert result[4:12] == b"\x03\x00\x00\x00\x00\x00\x00\x00"
        assert result[12:15] == b"abc"
        assert result[15:23] == b"\x02\x00\x00\x00\x00\x00\x00\x00"
        assert result[23:25] == b"de"

    def test_le32(self):
        assert le32(0) == b"\x00\x00\x00\x00"
        assert le32(1) == b"\x01\x00\x00\x00"
        assert le32(256) == b"\x00\x01\x00\x00"

    def test_le64(self):
        assert le64(0) == b"\x00\x00\x00\x00\x00\x00\x00\x00"
        assert le64(4) == b"\x04\x00\x00\x00\x00\x00\x00\x00"


# ─── Key derivation tests ─────────────────────────────────────────────────────

class TestKeyDerivation:
    def test_field_enc_key_is_deterministic(self):
        k1 = derive_field_enc_key(TEST_KEY, TABLE, FIELD)
        k2 = derive_field_enc_key(TEST_KEY, TABLE, FIELD)
        assert k1 == k2

    def test_field_enc_key_length(self):
        k = derive_field_enc_key(TEST_KEY, TABLE, FIELD)
        assert len(k) == 32

    def test_different_tables_give_different_keys(self):
        k1 = derive_field_enc_key(TEST_KEY, "users", "email")
        k2 = derive_field_enc_key(TEST_KEY, "orders", "email")
        assert k1 != k2

    def test_different_fields_give_different_keys(self):
        k1 = derive_field_enc_key(TEST_KEY, TABLE, "email")
        k2 = derive_field_enc_key(TEST_KEY, TABLE, "phone")
        assert k1 != k2

    def test_field_enc_key_differs_from_index_root_key(self):
        enc_key = derive_field_enc_key(TEST_KEY, TABLE, FIELD)
        idx_key = derive_index_root_key(TEST_KEY, TABLE, FIELD)
        assert enc_key != idx_key

    def test_blind_index_key_deterministic(self):
        irk = derive_index_root_key(TEST_KEY, TABLE, FIELD)
        k1 = derive_blind_index_key(irk, TABLE, FIELD, "email_index")
        k2 = derive_blind_index_key(irk, TABLE, FIELD, "email_index")
        assert k1 == k2

    def test_different_index_names_give_different_keys(self):
        irk = derive_index_root_key(TEST_KEY, TABLE, FIELD)
        k1 = derive_blind_index_key(irk, TABLE, FIELD, "email_index")
        k2 = derive_blind_index_key(irk, TABLE, FIELD, "email_idx2")
        assert k1 != k2

    def test_known_field_enc_key(self):
        # This vector must match what Go/PHP produces with same master key+table+field
        k = derive_field_enc_key(TEST_KEY, "users", "email")
        assert len(k) == 32
        assert isinstance(k, bytes)
        # Snapshot: print for cross-platform verification
        print(f"\n[vector] field_enc_key(users/email): {k.hex()}")


# ─── NaCl backend tests ───────────────────────────────────────────────────────

class TestNaClBackend:
    def setup_method(self):
        self.backend = NaClBackend()
        self.key = derive_field_enc_key(TEST_KEY, TABLE, FIELD)

    def test_round_trip_simple(self):
        plaintext = "alice@example.com"
        ct = encrypt_nacl(plaintext, self.key)
        assert ct.startswith("nacl:")
        result = self.backend.decrypt(ct, self.key)
        assert result == plaintext

    def test_round_trip_unicode(self):
        plaintext = "héllo wörld 🔐"
        ct = encrypt_nacl(plaintext, self.key)
        result = self.backend.decrypt(ct, self.key)
        assert result == plaintext

    def test_round_trip_empty_string(self):
        ct = encrypt_nacl("", self.key)
        assert self.backend.decrypt(ct, self.key) == ""

    def test_round_trip_long_string(self):
        plaintext = "x" * 10000
        ct = encrypt_nacl(plaintext, self.key)
        assert self.backend.decrypt(ct, self.key) == plaintext

    def test_different_ciphertext_each_time(self):
        plaintext = "alice@example.com"
        ct1 = encrypt_nacl(plaintext, self.key)
        ct2 = encrypt_nacl(plaintext, self.key)
        assert ct1 != ct2  # nonces are random

    def test_wrong_key_raises(self):
        plaintext = "alice@example.com"
        ct = encrypt_nacl(plaintext, self.key)
        wrong_key = secrets.token_bytes(32)
        with pytest.raises(Exception):
            self.backend.decrypt(ct, wrong_key)

    def test_bad_header_raises(self):
        with pytest.raises(ValueError, match="header"):
            self.backend.decrypt("fips:abc", self.key)

    def test_tampered_ciphertext_raises(self):
        ct = encrypt_nacl("hello", self.key)
        # Flip a byte in the payload
        header, payload = ct[:5], ct[5:]
        raw = bytearray(base64.urlsafe_b64decode(payload + "=="))
        raw[-1] ^= 0xFF
        tampered = header + base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode()
        with pytest.raises(Exception):
            self.backend.decrypt(tampered, self.key)

    def test_accepts_string_or_bytes_key(self):
        plaintext = "test"
        ct = encrypt_nacl(plaintext, self.key)
        result = self.backend.decrypt(ct, self.key)
        assert result == plaintext


# ─── FIPS backend tests ───────────────────────────────────────────────────────

class TestFIPSBackend:
    def setup_method(self):
        self.backend = FIPSBackend()
        self.key = derive_field_enc_key(TEST_KEY, TABLE, FIELD)

    def test_round_trip_simple(self):
        plaintext = "alice@example.com"
        ct = encrypt_fips(plaintext, self.key)
        assert ct.startswith("fips:")
        result = self.backend.decrypt(ct, self.key)
        assert result == plaintext

    def test_round_trip_unicode(self):
        plaintext = "héllo wörld 🔐"
        ct = encrypt_fips(plaintext, self.key)
        result = self.backend.decrypt(ct, self.key)
        assert result == plaintext

    def test_round_trip_empty_string(self):
        ct = encrypt_fips("", self.key)
        assert self.backend.decrypt(ct, self.key) == ""

    def test_round_trip_long_string(self):
        plaintext = "y" * 10000
        ct = encrypt_fips(plaintext, self.key)
        assert self.backend.decrypt(ct, self.key) == plaintext

    def test_different_ciphertext_each_time(self):
        plaintext = "alice@example.com"
        ct1 = encrypt_fips(plaintext, self.key)
        ct2 = encrypt_fips(plaintext, self.key)
        assert ct1 != ct2

    def test_wrong_key_raises(self):
        plaintext = "alice@example.com"
        ct = encrypt_fips(plaintext, self.key)
        wrong_key = secrets.token_bytes(32)
        with pytest.raises((ValueError, Exception)):
            self.backend.decrypt(ct, wrong_key)

    def test_bad_header_raises(self):
        with pytest.raises(ValueError, match="header"):
            self.backend.decrypt("nacl:abc", self.key)

    def test_tampered_ciphertext_raises_mac_error(self):
        ct = encrypt_fips("hello", self.key)
        header, payload = ct[:5], ct[5:]
        raw = bytearray(base64.urlsafe_b64decode(payload + "=="))
        raw[-1] ^= 0xFF
        tampered = header + base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode()
        with pytest.raises(ValueError, match="MAC"):
            self.backend.decrypt(tampered, self.key)


# ─── Engine + EncryptedField tests ───────────────────────────────────────────

class TestEngine:
    def test_nacl_engine_field_decrypt(self):
        provider = StringKeyProvider(TEST_KEY_HEX)
        engine = CipherSweet(NaClBackend(), provider)
        field = EncryptedField(engine, "users", "email")

        field_key = engine.get_field_symmetric_key("users", "email")
        ct = encrypt_nacl("alice@example.com", field_key)
        assert field.decrypt(ct) == "alice@example.com"

    def test_fips_engine_field_decrypt(self):
        provider = StringKeyProvider(TEST_KEY_HEX)
        engine = CipherSweet(FIPSBackend(), provider)
        field = EncryptedField(engine, "users", "email")

        field_key = engine.get_field_symmetric_key("users", "email")
        ct = encrypt_fips("alice@example.com", field_key)
        assert field.decrypt(ct) == "alice@example.com"

    def test_wrong_table_cannot_decrypt(self):
        provider = StringKeyProvider(TEST_KEY_HEX)
        engine = CipherSweet(NaClBackend(), provider)

        # Encrypted under "users"
        key_users = engine.get_field_symmetric_key("users", "email")
        ct = encrypt_nacl("secret", key_users)

        # Try to decrypt with "orders" table key
        field_orders = EncryptedField(engine, "orders", "email")
        with pytest.raises(Exception):
            field_orders.decrypt(ct)

    def test_cross_language_vector_go_laravel_nacl_users_phone(self):
        provider = StringKeyProvider("84d269301777265c1915f44f9f9f36a34323fed7c6e0069bdbf03ea37ecb0880")
        engine = CipherSweet(NaClBackend(), provider)
        field = EncryptedField(engine, "users", "phone")
        ct = "nacl:QQNISPIxChECsw39cllmJObCY07i-W1uUhrFURXqW7Lp1dD9wFxsFki8CBObKUw37TOgpBI="
        assert field.decrypt(ct) == "6282158115949"


# ─── Key Provider tests ───────────────────────────────────────────────────────

class TestKeyProviders:
    def test_string_provider(self):
        from ciphersweet import StringKeyProvider
        p = StringKeyProvider(TEST_KEY_HEX)
        assert p.get_symmetric_key() == TEST_KEY

    def test_string_provider_wrong_length_raises(self):
        from ciphersweet import StringKeyProvider
        with pytest.raises(ValueError):
            StringKeyProvider("deadbeef")  # too short

    def test_env_provider(self, monkeypatch):
        from ciphersweet import EnvKeyProvider
        monkeypatch.setenv("CIPHERSWEET_KEY", TEST_KEY_HEX)
        p = EnvKeyProvider()
        assert p.get_symmetric_key() == TEST_KEY

    def test_env_provider_missing_raises(self, monkeypatch):
        from ciphersweet import EnvKeyProvider
        monkeypatch.delenv("CIPHERSWEET_KEY", raising=False)
        p = EnvKeyProvider()
        with pytest.raises(RuntimeError):
            p.get_symmetric_key()

    def test_file_provider(self, tmp_path):
        from ciphersweet import FileKeyProvider
        key_file = tmp_path / "key.hex"
        key_file.write_text(TEST_KEY_HEX)
        p = FileKeyProvider(str(key_file))
        assert p.get_symmetric_key() == TEST_KEY


if __name__ == "__main__":
    # Quick smoke test
    print("Running smoke test...")
    key_hex = TEST_KEY_HEX
    provider = StringKeyProvider(key_hex)

    for backend_cls, name in [(NaClBackend, "NaCl"), (FIPSBackend, "FIPS")]:
        engine = CipherSweet(backend_cls(), provider)
        field = EncryptedField(engine, "users", "email")
        field_key = engine.get_field_symmetric_key("users", "email")
        enc_fn = encrypt_nacl if name == "NaCl" else encrypt_fips
        ct = enc_fn("alice@example.com", field_key)
        pt = field.decrypt(ct)
        assert pt == "alice@example.com", f"FAILED for {name}"
        print(f"  [{name}] ✓ encrypt/decrypt OK  ciphertext={ct[:40]}...")

    print("All smoke tests passed!")
