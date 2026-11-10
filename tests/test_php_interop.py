"""Cross-checks against values produced by paragonie/ciphersweet v4 under
PHP 8.3 (tests/vectors/generate_php_interop.php -> php_interop.json).

They cover everything the upstream vectors do not: Unicode plaintexts,
literal and multi-value AAD, optional/nullable types, typed and slow indexes,
compound indexes with mixed value types, encrypted JSON, multi-row
auto-bound context and extension keys.

The reverse direction (PHP decrypting rows, fields and JSON encrypted by this
package) was checked with ``vectors/check_python_output.php``.
"""

import pytest

from ciphersweet import (
    AAD,
    AlphaCharactersOnly,
    BlindIndex,
    BoringCrypto,
    CipherSweet,
    Compound,
    EncryptedField,
    EncryptedMultiRows,
    EncryptedRow,
    FIPSCrypto,
    FirstCharacter,
    JsonFieldMap,
    LastFourDigits,
    Lowercase,
    ModernCrypto,
    StringProvider,
)
from ciphersweet._util import php_float_to_string
from conftest import load_vectors

VEC = load_vectors("php_interop.json")
BACKENDS = {"nacl": ModernCrypto, "fips": FIPSCrypto, "brng": BoringCrypto}


@pytest.fixture(params=sorted(VEC["backends"]))
def case(request):
    name = request.param
    engine = CipherSweet(StringProvider(VEC["key"]), BACKENDS[name]())
    return engine, VEC["backends"][name]


def build_field(engine):
    return (
        EncryptedField(engine, "contacts", "email")
        .add_blind_index(BlindIndex("email_lower", [Lowercase()], 32, True))
        .add_blind_index(BlindIndex("email_first", [FirstCharacter()], 8, True))
        .add_blind_index(BlindIndex("email_alpha", [AlphaCharactersOnly()], 300, True))
        .add_blind_index(BlindIndex("email_slow", [Lowercase()], 64, False))
    )


def build_row(engine):
    row = (
        EncryptedRow(engine, "users")
        .add_text_field("name", "id")
        .add_integer_field("age")
        .add_float_field("score")
        .add_boolean_field("active")
        .add_optional_text_field("nickname")
        .add_optional_integer_field("maybe_int")
        .add_optional_boolean_field("maybe_bool")
        .add_text_field("ssn", AAD(["id", "tenant"], ["v1", "10", "9"]))
    )
    row.add_blind_index("ssn", BlindIndex("ssn_last4", [LastFourDigits()], 16, True))
    row.add_blind_index("age", BlindIndex("age_idx", [], 32, True))
    row.add_blind_index("active", BlindIndex("active_idx", [], 8, True))
    row.add_blind_index("score", BlindIndex("score_idx", [], 32, True))
    compound = row.create_compound_index("ssn_active", ["ssn", "active", "score", "age", "name"], 64, True)
    compound.add_transform("ssn", LastFourDigits())
    row.create_compound_index("name_slow", ["name", "nickname"], 32, False)
    return row, compound


def test_field(case):
    engine, vec = case
    field = build_field(engine)
    v = vec["field"]
    assert field.decrypt_value(v["ct"]) == v["plaintext"]
    assert field.decrypt_value(v["ct_aad"], v["aad"]) == v["plaintext"]
    assert field.get_all_blind_indexes(v["plaintext"]) == v["indexes"]
    assert field.get_blind_index_types() == v["types"]


def test_row(case):
    engine, vec = case
    row, compound = build_row(engine)
    v = vec["row"]
    assert row.decrypt_row(v["ciphertext"]) == v["plaintext"]
    assert row.get_all_blind_indexes(v["plaintext"]) == v["indexes"]
    assert compound.get_packed(v["plaintext"]).decode() == v["packed"]
    assert row.get_compound_index_type("ssn_active") == v["compound_type"]
    row.set_typed_indexes(True)
    assert row.get_all_blind_indexes(v["plaintext"]) == v["typed_indexes"]


def test_row_nulls_stay_plaintext(case):
    engine, vec = case
    v = vec["row"]
    assert v["ciphertext"]["nickname"] is None
    assert v["ciphertext"]["maybe_bool"] is None  # optional types skip NULL


def test_json(case):
    engine, vec = case
    field_map = (
        JsonFieldMap()
        .add_text_field(["profile", "name"])
        .add_integer_field(["profile", "age"])
        .add_boolean_field(["flags", 0])
        .add_float_field("balance")
    )
    row = EncryptedRow(engine, "docs").add_json_field("doc", field_map, "id")
    v = vec["json"]
    assert field_map.to_string() == v["map"]
    assert JsonFieldMap.from_string(v["map"]).get_mapping() == field_map.get_mapping()
    assert row.decrypt_row(v["ciphertext"]) == v["plaintext"]


def test_multi_rows(case):
    engine, vec = case
    multi = (
        EncryptedMultiRows(engine, False, True)
        .add_text_field("orders", "note")
        .add_integer_field("items", "qty")
    )
    multi.set_primary_key_column_name("orders", "id")
    v = vec["multi"]
    assert multi.decrypt_many_rows(v["ciphertext"]) == v["plaintext"]


def test_extension_key(case):
    engine, vec = case
    assert engine.get_extension_key("my-ext", "a", "b").get_raw_key().hex() == vec["ext_key"]


@pytest.mark.parametrize("value, expected", VEC["floats"])
def test_php_float_strings(value, expected):
    assert php_float_to_string(float(value)) == expected


def test_compound_json_encoding():
    packed = Compound()({"a": "x/y", "b": 1, "c": None, "d": True, "e": 2.5, "f": {"n": "ü"}, "g": []})
    assert packed.decode() == VEC["compound"][0]


@pytest.mark.parametrize(
    "backend, expected",
    [
        (ModernCrypto, "efefea1217a1d74f60760e0cddef0e1ddcc58d048f2a50ba3606d5bf0a68af9f"),
        (BoringCrypto, "efefea1217a1d74f60760e0cddef0e1ddcc58d048f2a50ba3606d5bf0a68af9f"),
        (FIPSCrypto, "d8ac859b518b7f2a1be1d9c6714070c18ecb8e0ee727f9c4942b86e407e92e1a"),
    ],
)
def test_derive_key_from_password(backend, expected):
    # Checked against PHP's deriveKeyFromPassword('password', '0123456789abcdef').
    key = backend().derive_key_from_password(b"password", b"0123456789abcdef")
    assert key.get_raw_key().hex() == expected
