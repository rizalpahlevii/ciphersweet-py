"""Ported from paragonie/ciphersweet tests/UtilTest.php, AADTest.php,
CompoundIndexTest.php and JsonFieldMapTest.php."""

import pytest

from ciphersweet import AAD, CompoundIndex, FastCompoundIndex, JsonFieldMap, LastFourDigits, constants
from ciphersweet._util import (
    and_mask,
    bool_to_chr,
    chr_to_bool,
    crc32c_hex,
    ctr_nonce_increase,
    float_to_string,
    int_to_string,
    pack,
    php_sort,
    string_to_float,
    string_to_int,
)
from ciphersweet.backend.fips import aes256ctr

AND_MASK = [
    ("ff", 4, "f0", "0f"),
    ("ffffffff", 16, "ffff", "ffff"),
    ("ffffffff", 17, "ffff80", "ffff01"),
    ("ffffffff", 18, "ffffc0", "ffff03"),
    ("ffffffff", 19, "ffffe0", "ffff07"),
    ("ffffffff", 20, "fffff0", "ffff0f"),
    ("ffffffff", 21, "fffff8", "ffff1f"),
    ("ffffffff", 22, "fffffc", "ffff3f"),
    ("ffffffff", 23, "fffffe", "ffff7f"),
    ("ffffffff", 24, "ffffff", "ffffff"),
    ("ffffffff", 32, "ffffffff", "ffffffff"),
    ("ffffffff", 64, "ffffffff00000000", "ffffffff00000000"),
    ("55f6778c", 11, "55e0", "5506"),
    ("55f6778c", 12, "55f0", "5506"),
    ("55f6778c", 13, "55f0", "5516"),
    ("55f6778c", 14, "55f4", "5536"),
    ("55f6778c", 15, "55f6", "5576"),
    ("55f6778c", 16, "55f6", "55f6"),
    ("55f6778c", 17, "55f600", "55f601"),
    ("55f6778c", 32, "55f6778c", "55f6778c"),
]


@pytest.mark.parametrize("data, bits, left, right", AND_MASK)
def test_and_mask(data, bits, left, right):
    assert and_mask(bytes.fromhex(data), bits).hex() == left
    assert and_mask(bytes.fromhex(data), bits, True).hex() == right


def test_aes256ctr_nist_vector():
    key = bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
    nonce = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    pt = bytes.fromhex(
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"
    )
    assert aes256ctr(pt, key, nonce).hex() == (
        "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c5"
        "2b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6"
    )


@pytest.mark.parametrize(
    "out, inp",
    [
        ("00000000000000000000000000000001", "00000000000000000000000000000000"),
        ("00000000000000000000000000000100", "000000000000000000000000000000ff"),
        ("0000000000000000000000000000ff00", "0000000000000000000000000000feff"),
        ("00000000000000000000000000000000", "ffffffffffffffffffffffffffffffff"),
    ],
)
def test_ctr_nonce_increase(out, inp):
    assert ctr_nonce_increase(bytes.fromhex(inp)).hex() == out


def test_scalar_encodings():
    assert bool_to_chr(True) == b"\x02"
    assert bool_to_chr(False) == b"\x01"
    assert bool_to_chr(None) == b"\x00"
    for v in (True, False, None):
        assert chr_to_bool(bool_to_chr(v)) is v
    with pytest.raises(ValueError):
        chr_to_bool(b"")
    with pytest.raises(ValueError):
        chr_to_bool(b"\x03")
    for n in (0, 1, -1, 2**63 - 1, -(2**63)):
        assert string_to_int(int_to_string(n)) == n
    assert int_to_string(-1) == b"\xff" * 8
    for f in (0.0, -1.5, 1e300, 3.1415):
        assert string_to_float(float_to_string(f)) == f


def test_pack():
    assert pack(["a", "bc"]).hex() == "02000000" + "0100000000000000" + "61" + "0200000000000000" + "6263"


def test_crc32c():
    assert crc32c_hex(b"123456789") == "e3069283"


def test_php_sort_numeric_strings():
    assert php_sort(["10", "9", "b", "a"]) == ["9", "10", "a", "b"]


# -- AAD (tests/AADTest.php) -------------------------------------------------


def test_aad_legacy():
    assert AAD.literal("foo").get_legacy()
    assert AAD.literal("foo").canonicalize() == b"foo"
    assert AAD.field("bar").canonicalize({"bar": "baz"}) == b"baz"


def test_aad_merge():
    merged = AAD.literal("foo").merge(AAD.field("bar"))
    assert merged.canonicalize({"bar": "baz"}).hex() == (
        "0200000000000000010000000000000001000000000000000300000000000000"
        "626172030000000000000062617a0300000000000000666f6f"
    )
    a5 = merged.add_literal("baz")
    a6 = a5.merge(AAD.literal("baz"))
    assert a5.canonicalize() == a6.canonicalize()


def test_aad_collapse():
    collapsed = AAD(["foo", "bar", "baz"], ["apple", "pear"]).get_collapsed(
        {"foo": "banana", "bar": "pineapple", "baz": "blueberry"}
    )
    assert collapsed.get_field_names() == []
    assert len(collapsed.get_literals()) == 5


def test_aad_field_order():
    assert AAD(["zebra", "apple"]).canonicalize({"zebra": "122", "apple": "123"}).hex() == (
        "02000000000000000200000000000000000000000000000005000000000000006170706c6503000000"
        "0000000031323305000000000000007a656272610300000000000000313232"
    )


# -- Compound (tests/CompoundIndexTest.php) ----------------------------------


@pytest.mark.parametrize("cls", [CompoundIndex, FastCompoundIndex])
def test_compound_packing(cls):
    args = ("ssn_hivstatus", ["ssn", "hivstatus"], 32) + ((True,) if cls is CompoundIndex else ())
    idx = cls(*args)
    idx.add_transform("ssn", LastFourDigits())
    assert (
        idx.get_packed({"ssn": "123-45-6789", "hivstatus": True})
        == b'{"ssn":"0400000000000000Njc4OQ==","hivstatus":true}'
    )
    assert (
        idx.get_packed({"ssn": "123-45-6789", "hivstatus": False})
        == b'{"ssn":"0400000000000000Njc4OQ==","hivstatus":false}'
    )


# -- JsonFieldMap (tests/JsonFieldMapTest.php) -------------------------------


def test_json_map_flatten():
    mapper = (
        JsonFieldMap()
        .add_field(["foo", "bar"], constants.TYPE_TEXT)
        .add_field(["bar", "baz"], constants.TYPE_INT)
    )
    original = mapper.to_string()
    mapped = mapper.get_mapping()
    assert [m["path"] for m in mapped] == [["foo", "bar"], ["bar", "baz"]]
    assert [m["flat"] for m in mapped] == ["$666f6f.$626172", "$626172.$62617a"]
    mapper.add_boolean_field(["foo", 0, "bar", 123])
    m3 = mapper.get_mapping()[2]
    assert m3["flat"] == "$666f6f.#0000000000000000.$626172.#000000000000007b"
    assert m3["path"] == ["foo", 0, "bar", 123]
    assert m3["type"] == constants.TYPE_BOOLEAN
    assert JsonFieldMap.from_string(original).get_mapping() == mapped
    assert JsonFieldMap.from_string(mapper.to_string()).get_mapping() == mapper.get_mapping()


def test_json_map_template():
    template = JsonFieldMap().add_text_field(["foo", "bar"]).add_integer_field(["bar", "baz"])
    parent = (
        JsonFieldMap()
        .add_map_field_from_template(["data", 0], template)
        .add_map_field_from_template(["data", 1], template)
    )
    assert parent.to_string() == (
        '3be7ae2c{"fields":{'
        '"$64617461.#0000000000000000.$666f6f.$626172":"string",'
        '"$64617461.#0000000000000000.$626172.$62617a":"int",'
        '"$64617461.#0000000000000001.$666f6f.$626172":"string",'
        '"$64617461.#0000000000000001.$626172.$62617a":"int"'
        "}}"
    )


def test_json_map_rejects_corruption():
    from ciphersweet import CipherSweetException

    s = JsonFieldMap().add_text_field("a").to_string()
    with pytest.raises(CipherSweetException):
        JsonFieldMap.from_string("00000000" + s[8:])
