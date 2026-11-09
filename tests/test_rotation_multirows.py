import pytest

from ciphersweet import (
    BlindIndex,
    BoringCrypto,
    CipherSweet,
    EncryptedField,
    EncryptedMultiRows,
    EncryptedRow,
    FieldRotator,
    FIPSCrypto,
    InvalidCiphertextException,
    ModernCrypto,
    MultiRowsRotator,
    RandomProvider,
    RowRotator,
)


def engines():
    return CipherSweet(RandomProvider(), FIPSCrypto()), CipherSweet(RandomProvider(), BoringCrypto())


def test_field_rotator():
    old_e, new_e = engines()
    old = EncryptedField(old_e, "t", "f")
    new = EncryptedField(new_e, "t", "f").add_blind_index(BlindIndex("idx", fast_hash=True))
    rotator = FieldRotator(old, new)
    ct = old.encrypt_value("hello")
    assert rotator.needs_re_encrypt(ct)
    new_ct, indexes = rotator.prepare_for_update(ct)
    assert not rotator.needs_re_encrypt(new_ct)
    assert new.decrypt_value(new_ct) == "hello"
    assert "idx" in indexes


def test_row_rotator():
    old_e, new_e = engines()
    old = EncryptedRow(old_e, "t").add_text_field("a")
    new = EncryptedRow(new_e, "t").add_text_field("a")
    rotator = RowRotator(old, new)
    enc = old.encrypt_row({"a": "x"})
    assert rotator.needs_re_encrypt(enc)
    new_row, _ = rotator.prepare_for_update(enc)
    assert not rotator.needs_re_encrypt(new_row)


def test_multi_rows_round_trip_and_rotation():
    old_e, new_e = engines()

    def build(engine):
        return (
            EncryptedMultiRows(engine)
            .add_text_field("orders", "note")
            .add_integer_field("items", "qty")
            .add_blind_index("orders", "note", BlindIndex("note_idx", fast_hash=True))
        )

    old, new = build(old_e), build(new_e)
    rows = {"orders": {"id": 1, "note": "door"}, "items": {"qty": 3}, "untouched": {"x": 1}}
    enc = old.encrypt_many_rows(rows)
    assert enc["untouched"] == {"x": 1}
    assert old.decrypt_many_rows(enc) == rows
    assert "note_idx" in old.get_all_blind_indexes(rows)["orders"]
    rotator = MultiRowsRotator(old, new)
    assert rotator.needs_re_encrypt(enc)
    new_rows, _ = rotator.prepare_for_update(enc)
    # like PHP, prepare_for_storage only returns the configured tables
    assert new.decrypt_many_rows(new_rows) == {k: v for k, v in rows.items() if k != "untouched"}


def test_multi_rows_auto_bind_context():
    engine = CipherSweet(RandomProvider(), ModernCrypto())
    # The primary key must be configured before the field is added.
    multi = EncryptedMultiRows(engine, auto_bind_context=True).set_primary_key_column_name("a", "id")
    multi.add_text_field("a", "secret")
    enc = multi.encrypt_many_rows({"a": {"id": 1, "secret": "s"}})
    assert multi.decrypt_many_rows(enc)["a"]["secret"] == "s"
    enc["a"]["id"] = 2
    with pytest.raises(InvalidCiphertextException):
        multi.decrypt_many_rows(enc)
