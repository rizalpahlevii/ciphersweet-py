import sqlite3

import pytest

from ciphersweet import BlindIndex, CipherSweet, EncryptedRow, FIPSCrypto, ModernCrypto, StringProvider
from ciphersweet.compat.go import GoBoringCrypto
from ciphersweet.laravel import (
    blind_index_records,
    engine_from_env,
    generate_key,
    where_blind_sql,
)
from ciphersweet.migrate import Dialect, Plan, index_width, laravel_blind_indexes_table

KEY = "4e1c44f87b4cdf21808762970b356891db180a9dd9850e7baf2a79ff3ab8a2fc"


def test_engine_from_env():
    engine = engine_from_env({"CIPHERSWEET_KEY": KEY})
    assert isinstance(engine.get_backend(), ModernCrypto)
    engine = engine_from_env({"CIPHERSWEET_BACKEND": "fips", "CIPHERSWEET_KEY": KEY})
    assert isinstance(engine.get_backend(), FIPSCrypto)
    assert len(generate_key()) == 64
    assert len(generate_key(base64=True)) == 44


def test_laravel_blind_index_table_round_trip():
    engine = engine_from_env({"CIPHERSWEET_KEY": KEY})
    users = EncryptedRow(engine, "users").add_text_field("email")
    users.add_blind_index("email", BlindIndex("email_index", fast_hash=True))

    db = sqlite3.connect(":memory:")
    db.executescript(laravel_blind_indexes_table(Dialect.SQLITE))
    db.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT)")
    for user_id, email in [(1, "a@example.com"), (2, "b@example.com")]:
        db.execute("INSERT INTO users VALUES (?, ?)", (user_id, users.encrypt_row({"email": email})["email"]))
        for rec in blind_index_records(users, {"email": email}, "App\\Models\\User", user_id):
            db.execute(
                "INSERT INTO blind_indexes (indexable_type, indexable_id, name, value) VALUES (?, ?, ?, ?)",
                (rec["indexable_type"], rec["indexable_id"], rec["name"], rec["value"]),
            )
    cond, params = where_blind_sql(
        "users", "id", "App\\Models\\User", users, "email", "email_index", "b@example.com", "?"
    )
    found = db.execute(f"SELECT id, email FROM users WHERE {cond}", params).fetchall()
    assert len(found) == 1 and found[0][0] == 2
    assert users.decrypt_row({"email": found[0][1]})["email"] == "b@example.com"


def test_migrate_plan():
    plan = Plan("users", Dialect.POSTGRESQL).add_encrypted_column("email").add_index_column("email_idx", 32)
    assert index_width(32) == 8
    up = plan.up()
    assert '"email" TEXT NULL' in up and "VARCHAR(8)" in up and "CREATE INDEX" in up
    assert "DROP COLUMN" in plan.down()
    db = sqlite3.connect(":memory:")
    db.executescript(
        Plan("t", Dialect.SQLITE).add_encrypted_column("a").add_index_column("a_idx").create_table()
    )
    with pytest.raises(ValueError):
        Plan("users; DROP TABLE x")


def test_go_boring_round_trip():
    engine = CipherSweet(StringProvider(KEY), GoBoringCrypto())
    row = EncryptedRow(engine, "users").add_text_field("email", "id")
    row.add_blind_index("email", BlindIndex("email_idx", fast_hash=True, filter_bits=32))
    enc = row.encrypt_row({"id": 1, "email": "a@example.com"})
    assert enc["email"].startswith("boring:") and not enc["email"].endswith("=")
    assert row.decrypt_row(enc)["email"] == "a@example.com"
    assert len(row.get_blind_index("email_idx", {"email": "a@example.com"})) == 8
