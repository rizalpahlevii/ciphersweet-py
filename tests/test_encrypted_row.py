"""Ported from paragonie/ciphersweet tests/EncryptedRowTest.php plus extra
round-trip coverage."""

import enum

import pytest

from ciphersweet import (
    AAD,
    ArrayKeyException,
    BlindIndex,
    CipherSweetException,
    EmptyFieldException,
    EncryptedRow,
    FIPSCrypto,
    InvalidAADException,
    InvalidCiphertextException,
    JsonFieldMap,
    LastFourDigits,
    ModernCrypto,
)
from conftest import make_engine


def example_row(engine, longer=False, fast=False):
    row = EncryptedRow(engine, "contacts").add_text_field("ssn").add_boolean_field("hivstatus")
    row.add_blind_index(
        "ssn", BlindIndex("contact_ssn_last_four", [LastFourDigits()], 64 if longer else 16, fast)
    )
    row.create_compound_index("contact_ssnlast4_hivstatus", ["ssn", "hivstatus"], 64 if longer else 16, fast)
    return row


def test_constructor(engine):
    row = EncryptedRow(engine, "test", True)
    assert row.get_typed_indexes()
    assert not row.get_flat_indexes()
    assert not row.get_permit_empty()


def test_index_from_partial_info():
    row_data = {"ssn": "123-45-6789", "hivstatus": True}
    fips = example_row(make_engine(FIPSCrypto), longer=True)
    fips.set_flat_indexes(True).add_text_field("extraneous")
    indexes = fips.get_all_blind_indexes(row_data)
    assert indexes["contact_ssn_last_four"] == "a88e74ada916ab9b"
    assert indexes["contact_ssnlast4_hivstatus"] == "9c3d53214ab71d7f"
    assert fips.get_blind_index("contact_ssn_last_four", row_data) == "a88e74ada916ab9b"

    nacl = example_row(make_engine(ModernCrypto), longer=True)
    nacl.set_flat_indexes(True).add_text_field("extraneous")
    indexes = nacl.get_all_blind_indexes(row_data)
    assert indexes["contact_ssn_last_four"] == "2acbcd1c7c55c1db"
    assert indexes["contact_ssnlast4_hivstatus"] == "1b8c1e1f8e122bd3"


def test_typed_indexes_and_types():
    row_data = {"extraneous": "this is unencrypted", "ssn": "123-45-6789", "hivstatus": True}
    row = example_row(make_engine(FIPSCrypto), longer=True)
    assert len(row.get_blind_index_objects_for_column("ssn")) == 1
    row.set_typed_indexes(True)
    indexes = row.get_all_blind_indexes(row_data)
    assert indexes["contact_ssn_last_four"] == {"type": "idlzpypmia6qu", "value": "a88e74ada916ab9b"}
    assert indexes["contact_ssnlast4_hivstatus"] == {"type": "dozudszz2yu5k", "value": "9c3d53214ab71d7f"}
    assert row.get_blind_index_type("contacts", "contact_ssn_last_four") == "xbobk6kf7kqcm"
    assert row.get_compound_index_type("contact_ssnlast4_hivstatus") == "dozudszz2yu5k"


class Colour(enum.Enum):
    RED = "red"


def test_round_trip_all_types(random_engine):
    row = (
        EncryptedRow(random_engine, "things")
        .add_text_field("text")
        .add_integer_field("int")
        .add_float_field("float")
        .add_boolean_field("bool")
        .add_optional_text_field("otext")
        .add_optional_integer_field("oint")
        .add_optional_float_field("ofloat")
        .add_optional_boolean_field("obool")
        .add_text_field("enum")
    )
    data = {
        "id": 1,
        "text": "héllo ✓",
        "int": -(2**63),
        "float": 3.14159,
        "bool": False,
        "otext": None,
        "oint": None,
        "ofloat": None,
        "obool": None,
        "enum": Colour.RED,
    }
    encrypted = row.encrypt_row(data)
    assert encrypted["id"] == 1
    assert encrypted["otext"] is None and encrypted["oint"] is None
    assert encrypted["obool"] is None
    for name in ("text", "int", "float", "bool", "enum"):
        assert encrypted[name].startswith(random_engine.get_backend().get_prefix())
    decrypted = row.decrypt_row(encrypted)
    assert decrypted == {**data, "enum": "red"}


def test_aad_binding(random_engine):
    row = EncryptedRow(random_engine, "contacts").add_text_field("message", "id")
    encrypted = row.encrypt_row({"id": 123, "message": "hi"})
    assert row.decrypt_row(encrypted)["message"] == "hi"
    encrypted["id"] = 124
    with pytest.raises(InvalidCiphertextException):
        row.decrypt_row(encrypted)


def test_multi_value_aad(random_engine):
    row = EncryptedRow(random_engine, "t").add_text_field("secret", AAD(["a", "b"], ["lit"]))
    enc = row.encrypt_row({"a": 1, "b": "x", "secret": "s"})
    assert row.decrypt_row(enc)["secret"] == "s"
    with pytest.raises(InvalidCiphertextException):
        row.decrypt_row({**enc, "b": "y"})


def test_auto_bind_primary_key(random_engine):
    row = EncryptedRow(random_engine, "t", primary_key_column_name="id")
    row.add_field("secret", auto_bind_context=True)
    enc = row.encrypt_row({"id": 5, "secret": "s"})
    with pytest.raises(InvalidCiphertextException):
        row.decrypt_row({**enc, "id": 6})
    with pytest.raises(CipherSweetException):
        row.encrypt_row({"secret": "s"})


def test_encrypted_field_cannot_be_aad(random_engine):
    row = EncryptedRow(random_engine, "t").add_text_field("a").add_text_field("b", "a")
    with pytest.raises(InvalidAADException):
        row.encrypt_row({"a": "1", "b": "2"})


def test_missing_fields(random_engine):
    row = EncryptedRow(random_engine, "t").add_text_field("a").add_text_field("b")
    with pytest.raises(ArrayKeyException):
        row.encrypt_row({"a": "x"})
    enc = row.encrypt_row({"a": "x", "b": "y"})
    del enc["b"]
    with pytest.raises(EmptyFieldException):
        row.decrypt_row(enc)
    assert row.set_permit_empty(True).decrypt_row(enc) == {"a": "x"}


def test_null_in_required_field(random_engine):
    row = EncryptedRow(random_engine, "t").add_text_field("a")
    with pytest.raises(TypeError):
        row.encrypt_row({"a": None})


def test_required_boolean_encrypts_null(random_engine):
    row = EncryptedRow(random_engine, "t").add_boolean_field("b")
    enc = row.encrypt_row({"b": None})
    assert enc["b"] is not None
    assert row.decrypt_row(enc)["b"] is None


def test_type_checks(random_engine):
    row = EncryptedRow(random_engine, "t").add_integer_field("n")
    with pytest.raises(TypeError):
        row.encrypt_row({"n": "12"})
    with pytest.raises(TypeError):
        row.encrypt_row({"n": True})


def test_json_field(random_engine):
    field_map = (
        JsonFieldMap().add_text_field(["a", "b"]).add_integer_field(["n"]).add_boolean_field(["list", 1])
    )
    row = EncryptedRow(random_engine, "t").add_json_field("doc", field_map)
    doc = {"a": {"b": "secret", "c": "plain"}, "n": 7, "list": [None, True], "other": 1.5}
    enc = row.encrypt_row({"doc": doc})
    assert isinstance(enc["doc"], str)
    assert row.decrypt_row(enc)["doc"] == doc
    assert row.get_json_field_map("doc") is field_map


def test_row_transform_compound(engine):
    row = EncryptedRow(engine, "t").add_text_field("first").add_text_field("last")
    idx = row.create_fast_compound_index("name", ["first", "last"], 32)
    idx.add_row_transform(lambda pieces: (pieces["first"] + pieces["last"]).lower())
    a = row.get_blind_index("name", {"first": "Ann", "last": "Lee"})
    b = row.get_blind_index("name", {"first": "aNN", "last": "LEE"})
    assert a == b


def test_prepare_row_for_storage(engine):
    row = example_row(engine, fast=True)
    data = {"ssn": "123-45-6789", "hivstatus": False}
    encrypted, indexes = row.prepare_row_for_storage(data)
    assert row.decrypt_row(encrypted) == data
    assert set(indexes) == {"contact_ssn_last_four", "contact_ssnlast4_hivstatus"}
