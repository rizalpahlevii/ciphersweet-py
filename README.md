# ciphersweet-py

Searchable field-level encryption for Python, **wire-compatible with
[paragonie/ciphersweet](https://github.com/paragonie/ciphersweet)** (PHP) and therefore with
Laravel apps that use [spatie/laravel-ciphersweet](https://github.com/spatie/laravel-ciphersweet).

Data encrypted by PHP decrypts in Python and the other way round, and blind indexes computed in
Python match the ones PHP stored, so both sides can search the same database. This is checked by
the upstream known-answer tests plus a second set of vectors generated with PHP CipherSweet v4
(see [`tests/vectors`](tests/vectors)).

It is the Python sibling of [ciphersweet-go](https://github.com/rizalpahlevii/ciphersweet-go).

## Installation

```bash
pip install ciphersweet-py
```

Requires Python 3.10+, [`cryptography`](https://pypi.org/project/cryptography/) and
[`PyNaCl`](https://pypi.org/project/PyNaCl/). The import name is `ciphersweet`.

## Quick start

```python
from ciphersweet import (
    BlindIndex, CipherSweet, EncryptedRow, LastFourDigits, Lowercase, ModernCrypto, StringProvider,
)

# 64 hex chars, e.g. from `openssl rand -hex 32` or `php artisan ciphersweet:generate-key`
engine = CipherSweet(StringProvider("4e1c44f8...a2fc"), ModernCrypto())

contacts = (
    EncryptedRow(engine, "contacts")
    .add_text_field("email")
    .add_text_field("ssn")
    .add_boolean_field("vip")
)
contacts.add_blind_index("email", BlindIndex("email_idx", [Lowercase()], 32, fast_hash=True))
contacts.add_blind_index("ssn", BlindIndex("ssn_last4", [LastFourDigits()], 16, fast_hash=True))

row = {"id": 1, "email": "Alice@Example.com", "ssn": "123-45-6789", "vip": True}
encrypted, indexes = contacts.prepare_row_for_storage(row)
# encrypted == {"id": 1, "email": "nacl:...", "ssn": "nacl:...", "vip": "nacl:..."}
# indexes   == {"email_idx": "1a2b3c4d", "ssn_last4": "9f0e"}

# Search: compute the index for the value you are looking for ...
needle = contacts.get_blind_index("email_idx", {"email": "alice@example.com"})
# ... SELECT * FROM contacts WHERE email_idx = :needle

assert contacts.decrypt_row(encrypted) == row
```

A single column can use `EncryptedField` instead:

```python
from ciphersweet import EncryptedField

ssn = EncryptedField(engine, "contacts", "ssn")
ssn.add_blind_index(BlindIndex("ssn_last4", [LastFourDigits()], 16, fast_hash=True))
ciphertext, indexes = ssn.prepare_for_storage("123-45-6789")
ssn.decrypt_value(ciphertext)  # "123-45-6789"
```

## Compatibility rules

To read or search data written by PHP you must use the same:

* **key** and **backend** (`nacl:`, `brng:` or `fips:` prefix on the ciphertext),
* **table and column names** (they are part of the key derivation),
* **field types** (`add_integer_field` stores 8 bytes, not the decimal text),
* **AAD sources**, and
* **blind index names, transformations, bit lengths and fast/slow setting.**

Note that `BlindIndex` defaults to a *slow* (Argon2id/PBKDF2) index, exactly like PHP. Pass
`fast_hash=True` (or use `FastBlindIndex`) for the fast one.

## Backends

| Class | Prefix | Algorithms | Notes |
| --- | --- | --- | --- |
| `BoringCrypto` | `brng:` | XChaCha20 + BLAKE2b-MAC, Argon2id | PHP's default when no backend is given; multi-tenant safe |
| `ModernCrypto` | `nacl:` | XChaCha20-Poly1305, BLAKE2b, Argon2id | Laravel's default (`CIPHERSWEET_BACKEND=nacl`) |
| `FIPSCrypto` | `fips:` | AES-256-CTR + HMAC-SHA-384, PBKDF2-SHA-384 | FIPS-approved primitives; multi-tenant safe |

`CipherSweet(provider)` without a backend uses `BoringCrypto`, the same as PHP.

## Field types

`EncryptedRow` (and `EncryptedMultiRows`) support the same types as PHP:

| Method | PHP constant | Python value |
| --- | --- | --- |
| `add_text_field` | `TYPE_TEXT` | `str` (or `bytes`) |
| `add_integer_field` | `TYPE_INT` | `int` (signed 64-bit) |
| `add_float_field` | `TYPE_FLOAT` | `float` |
| `add_boolean_field` | `TYPE_BOOLEAN` | `bool` or `None` |
| `add_json_field` | `TYPE_JSON` | `dict`/`list` with a `JsonFieldMap` |
| `add_optional_*_field` | `TYPE_OPTIONAL_*` | as above, `None` stays unencrypted |

Text that is not valid UTF-8 decrypts to `bytes`. `Enum` values are stored as their value.

## Additional authenticated data

```python
from ciphersweet import AAD

row = EncryptedRow(engine, "messages").add_text_field("body", "id")  # bind to the id column
row.add_text_field("subject", AAD(["id", "tenant_id"], ["v1"]))      # several values
encrypted = row.encrypt_row({"id": 7, "tenant_id": 3, "body": "hi", "subject": "hello"})
```

Changing `id` afterwards makes decryption fail, which stops ciphertexts being copied between rows.
`EncryptedRow(..., primary_key_column_name="id")` with `add_field(..., auto_bind_context=True)`
does the same automatically.

## Compound indexes and transformations

```python
idx = contacts.create_fast_compound_index("ssn_vip", ["ssn", "vip"], 32)
idx.add_transform("ssn", LastFourDigits())
```

Built-in transformations: `Lowercase`, `AlphaCharactersOnly`, `AlphaNumericCharactersOnly`,
`DigitsOnly`, `FirstCharacter`, `LastFourDigits` and `Compound`. Any callable works as a custom
transformation; return `str` or `bytes`.

## Encrypted JSON

```python
from ciphersweet import JsonFieldMap

profile_map = JsonFieldMap().add_text_field(["address", "street"]).add_integer_field("age")
users = EncryptedRow(engine, "users").add_json_field("profile", profile_map)
```

Only the mapped paths are encrypted, each under its own derived key; the rest stays readable.

## Key providers

| Provider | Key source |
| --- | --- |
| `StringProvider(key)` | 64 hex chars, 44 base64url chars, or 32 raw bytes |
| `EnvProvider("CIPHERSWEET_KEY")` | environment variable, read on each use |
| `FileProvider(path)` | file contents as raw bytes (PHP behaviour); `encoding="auto"` accepts hex/base64url |
| `RandomProvider()` | random key for tests only |
| `MultiTenantProvider({...})` | one provider per tenant (with `FIPSCrypto` or `BoringCrypto`) |

## Laravel (spatie/laravel-ciphersweet)

```python
from ciphersweet import BlindIndex, EncryptedRow
from ciphersweet.laravel import blind_index_records, engine_from_env, where_blind_sql

engine = engine_from_env()            # CIPHERSWEET_BACKEND, CIPHERSWEET_PROVIDER, CIPHERSWEET_KEY
users = EncryptedRow(engine, "users") # the model's table name
users.add_text_field("email")         # mirror configureCipherSweet()
users.add_blind_index("email", BlindIndex("email_index", fast_hash=True))

user = users.decrypt_row(db_row)

# rows for the shared `blind_indexes` table, as updateBlindIndexes() writes them
records = blind_index_records(users, user, "App\\Models\\User", user["id"])

# the equivalent of User::whereBlind('email', 'email_index', $email)
condition, params = where_blind_sql(
    "users", "id", "App\\Models\\User", users, "email", "email_index", "alice@example.com"
)
cursor.execute(f"SELECT * FROM users WHERE {condition}", params)
```

`ciphersweet.migrate.laravel_blind_indexes_table()` returns the DDL for the `blind_indexes` table.

## ciphersweet-go

ciphersweet-go's `nacl:` ciphertexts and fast blind indexes follow the PHP format, so
`ModernCrypto` reads them. For its Go-only parts, see `ciphersweet.compat.go`:

* `GoBoringCrypto` reads and writes the Go `boring:` (AES-256-GCM) format.
* `GoModernCrypto` reproduces Go's Argon2id parameters for slow indexes.

Install the extra for these slow indexes: `pip install "ciphersweet-py[go]"`. This module
mirrors the Go source but has not yet been tested against values produced by the Go library.

## Key rotation

`FieldRotator`, `RowRotator` and `MultiRowsRotator` re-encrypt data from an old engine (key or
backend) to a new one:

```python
from ciphersweet import FieldRotator

rotator = FieldRotator(old_field, new_field)
if rotator.needs_re_encrypt(ciphertext):
    ciphertext, indexes = rotator.prepare_for_update(ciphertext)
```

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check src tests && ruff format --check src tests && mypy
python -m build && twine check dist/*
```

## Publishing to PyPI

Releases are published by `.github/workflows/publish.yml` using PyPI trusted publishing:

1. On pypi.org, add a trusted publisher for `rizalpahlevii/ciphersweet-py`, workflow
   `publish.yml`, environment `pypi`.
2. Bump `__version__` in `src/ciphersweet/__init__.py` and update `CHANGELOG.md`.
3. Create a GitHub release (e.g. tag `v0.1.0`). The workflow builds and uploads the package.

## Not yet ported

`EncryptedFile` (stream encryption of whole files) and the `FieldIndexPlanner`.

## License

MIT
