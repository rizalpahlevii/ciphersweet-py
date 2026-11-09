"""Ported from paragonie/ciphersweet tests/EncryptedFieldTest.php."""

import os

import pytest

from ciphersweet import (
    BlindIndex,
    BlindIndexNameCollisionException,
    BlindIndexNotFoundException,
    EncryptedField,
    FIPSCrypto,
    InvalidCiphertextException,
    LastFourDigits,
    ModernCrypto,
)
from conftest import make_engine


def example_field(engine, longer=False, fast=False):
    return (
        EncryptedField(engine, "contacts", "ssn")
        .add_blind_index(BlindIndex("contact_ssn_last_four", [LastFourDigits()], 64 if longer else 16, fast))
        .add_blind_index(BlindIndex("contact_ssn_last_4", [LastFourDigits()], 64 if longer else 16, fast))
        .add_blind_index(BlindIndex("contact_ssn", [], 128 if longer else 32, fast))
    )


def test_constructor(engine):
    assert EncryptedField(engine, "test", "field", True).get_typed_indexes()


def test_encrypt_decrypt_with_aad(random_engine):
    field = example_field(random_engine)
    message = "This is a test message: " + os.urandom(8).hex()
    ct = field.encrypt_value(message)
    assert ct.startswith(random_engine.get_backend().get_prefix())
    assert field.decrypt_value(ct) == message

    aad = "Test AAD: " + os.urandom(16).hex()
    ct_aad = field.encrypt_value(message, aad)
    assert field.decrypt_value(ct_aad, aad) == message
    with pytest.raises(InvalidCiphertextException):
        field.decrypt_value(ct, aad)
    with pytest.raises(InvalidCiphertextException):
        field.decrypt_value(ct_aad)


def test_binary_plaintext(random_engine):
    field = EncryptedField(random_engine, "t", "f")
    data = bytes(range(256))
    assert field.decrypt_value_bytes(field.encrypt_value(data)) == data


def test_tampering_detected(random_engine):
    field = EncryptedField(random_engine, "t", "f")
    ct = field.encrypt_value("hello")
    tampered = ct[:-3] + ("A" if ct[-3] != "A" else "B") + ct[-2:]
    with pytest.raises(InvalidCiphertextException):
        field.decrypt_value(tampered)
    with pytest.raises(InvalidCiphertextException):
        field.decrypt_value("xxxx:" + ct[5:])


def test_wrong_field_key(random_engine):
    a = EncryptedField(random_engine, "t", "a")
    b = EncryptedField(random_engine, "t", "b")
    with pytest.raises(InvalidCiphertextException):
        b.decrypt_value(a.encrypt_value("secret"))


FIPS_SLOW = {
    ("111-11-1111", "contact_ssn_last_four"): "334b",
    ("111-11-2222", "contact_ssn_last_four"): "7947",
    ("123-45-6788", "contact_ssn_last_four"): "d5ac",
    ("123-45-6789", "contact_ssn_last_four"): "a88e",
    ("invalid guess 123", "contact_ssn"): "ee10e07b",
    ("123-45-6789", "contact_ssn"): "9a15fe14",
}
FIPS_FAST = {
    ("111-11-1111", "contact_ssn_last_four"): "924b",
    ("111-11-2222", "contact_ssn_last_four"): "be3b",
    ("123-45-6788", "contact_ssn_last_four"): "3cd3",
    ("123-45-6789", "contact_ssn_last_four"): "4bb1",
    ("invalid guess 123", "contact_ssn"): "256e1182",
    ("123-45-6789", "contact_ssn"): "d2a774dc",
}
MODERN_SLOW = {
    ("111-11-1111", "contact_ssn_last_four"): "32ae",
    ("111-11-2222", "contact_ssn_last_four"): "e538",
    ("123-45-6788", "contact_ssn_last_four"): "8d1a",
    ("123-45-6789", "contact_ssn_last_four"): "2acb",
    ("invalid guess 123", "contact_ssn"): "499db508",
    ("123-45-6789", "contact_ssn"): "311314c1",
}
MODERN_FAST = {
    ("111-11-1111", "contact_ssn_last_four"): "7843",
    ("111-11-2222", "contact_ssn_last_four"): "d246",
    ("123-45-6788", "contact_ssn_last_four"): "4882",
    ("123-45-6789", "contact_ssn_last_four"): "92c8",
    ("invalid guess 123", "contact_ssn"): "b6fd11a1",
    ("123-45-6789", "contact_ssn"): "30c7cc68",
}
TYPES = {
    "fips": {"contact_ssn_last_four": "idlzpypmia6qu", "contact_ssn": "stfodrsbpd4ls"},
    "nacl": {"contact_ssn_last_four": "3dywyifwujcu2", "contact_ssn": "2iztg3wbd7j5a"},
}


@pytest.mark.parametrize(
    "backend, fast, expected, types",
    [
        (FIPSCrypto, False, FIPS_SLOW, TYPES["fips"]),
        (FIPSCrypto, True, FIPS_FAST, TYPES["fips"]),
        (ModernCrypto, False, MODERN_SLOW, TYPES["nacl"]),
        (ModernCrypto, True, MODERN_FAST, TYPES["nacl"]),
    ],
)
def test_blind_index_vectors(backend, fast, expected, types):
    field = example_field(make_engine(backend), fast=fast)
    for (plaintext, name), value in expected.items():
        assert field.get_blind_index(plaintext, name) == value
    field.set_typed_indexes(True)
    for (plaintext, name), value in expected.items():
        assert field.get_blind_index(plaintext, name) == {"type": types[name], "value": value}
    for name, type_ in types.items():
        assert field.get_blind_index_type(name) == type_


def test_random_key_gives_different_index(random_engine):
    field = example_field(random_engine, longer=True, fast=True)
    assert field.get_blind_index("123-45-6789", "contact_ssn") != "499db5085e715c2f167c1e2c02f1c80f"


def test_prepare_for_storage(engine):
    field = example_field(engine, fast=True)
    ct, indexes = field.prepare_for_storage("123-45-6789")
    assert field.decrypt_value(ct) == "123-45-6789"
    assert set(indexes) == {"contact_ssn_last_four", "contact_ssn_last_4", "contact_ssn"}


def test_index_errors(engine):
    field = example_field(engine, fast=True)
    with pytest.raises(BlindIndexNotFoundException):
        field.get_blind_index("x", "nope")
    with pytest.raises(BlindIndexNameCollisionException):
        field.add_blind_index(BlindIndex("contact_ssn"))
