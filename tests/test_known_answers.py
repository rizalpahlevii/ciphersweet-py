"""Known-answer tests taken verbatim from paragonie/ciphersweet's test suite
(tests/KnownAnswers/*.json, tests/Interop/JavaScriptTest.php)."""

import pytest

from ciphersweet import (
    BlindIndex,
    BoringCrypto,
    CipherSweet,
    EncryptedRow,
    FIPSCrypto,
    ModernCrypto,
    StringProvider,
    SymmetricKey,
)
from conftest import load_vectors


@pytest.mark.parametrize(
    "filename, backend",
    [("nacl.json", ModernCrypto), ("nist.json", FIPSCrypto), ("boring.json", BoringCrypto)],
)
def test_upstream_vectors(filename, backend):
    vectors = load_vectors(filename)
    engine = CipherSweet(StringProvider(bytes.fromhex(vectors["key"])), backend())
    case = vectors["testCases"]["simple"]
    row = (
        EncryptedRow(engine, case["tableName"])
        .add_text_field("name")
        .add_integer_field("age")
        .add_float_field("grade")
        .add_boolean_field("pass")
    )
    for name, spec in case["indexes"].items():
        assert spec["transforms"] == []
        row.add_blind_index(spec["field"], BlindIndex(name, [], spec["filter-bits"], spec["fast"]))

    for ciphertext, plaintext, blind in zip(case["ciphertext"], case["plaintext"], case["blind"], strict=True):
        decrypted = row.decrypt_row(ciphertext)
        assert decrypted == plaintext
        assert type(decrypted["age"]) is int
        assert type(decrypted["grade"]) is float
        assert type(decrypted["pass"]) is bool
        assert row.get_all_blind_indexes(plaintext) == blind
        # and our own ciphertexts round-trip
        assert row.decrypt_row(row.encrypt_row(plaintext)) == plaintext


@pytest.mark.parametrize(
    "key, ciphertext",
    [
        (
            "ff" * 32,
            "brng:m3y71cMwhTB2e8YjPLzZ2mwBoMRP1BgqVs_He47bRT5DJbWVBwG_cNsn6xvsl4rT2Cu1QSOEFt_lRECl3w524LlzGwgZ30UDm1KfgaTi9scjmu4=",
        ),
        (
            "0b036de5605144ea7aeed8bd3a191c08fe1b0ed69d9c8ba0dcbe82372451bb31",
            "brng:s0oCG2qoJMTWNreJ3AYQhTYSL423gsDYFKmSMDBzOUubIbiNPWSFZmD8uXMO5dmAhuCf5dvTCtfVvl8MADVL0dmub-znB7nEDYH2eMJBCmX-Qyc=",
        ),
    ],
)
def test_javascript_interop(key, ciphertext):
    plaintext = BoringCrypto().decrypt(ciphertext, SymmetricKey(bytes.fromhex(key)))
    assert plaintext == b"This is just a test message"
