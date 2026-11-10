# Getting started

## Install

```bash
pip install ciphersweet-py
```

This pulls in [`cryptography`](https://pypi.org/project/cryptography/) and
[`PyNaCl`](https://pypi.org/project/PyNaCl/). If you need to read slow blind indexes written by
ciphersweet-go, install the `go` extra instead: `pip install "ciphersweet-py[go]"`.

## Generate a key

CipherSweet uses one 256-bit root key and derives a separate key for every table, column and
index from it. Generate one and keep it in your secret store:

```bash
openssl rand -hex 32
```

From Python, [`ciphersweet.laravel.generate_key()`][ciphersweet.laravel.generate_key] returns
the same 64 hex characters that `php artisan ciphersweet:generate-key` prints.

!!! warning
    Losing the key means losing the data. Changing the key means re-encrypting every row; see
    [Key rotation](guide/key-rotation.md).

## Create an engine

The engine combines a [key provider](guide/key-providers.md) with a [backend](guide/backends.md):

```python
from ciphersweet import CipherSweet, EnvProvider, ModernCrypto

engine = CipherSweet(EnvProvider("CIPHERSWEET_KEY"), ModernCrypto())
```

`CipherSweet(provider)` with no backend uses `BoringCrypto`, which is also PHP's default. Laravel
defaults to `ModernCrypto` (`CIPHERSWEET_BACKEND=nacl`). Pick the one the other side uses.

## Encrypt a row

Describe the table once, then encrypt and decrypt plain dictionaries:

```python
from ciphersweet import BlindIndex, EncryptedRow, LastFourDigits, Lowercase

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
```

Columns you did not register (here `id`) pass through unchanged. Store `encrypted` in the table
and each index value in its own column, for example `email_idx`.

## Search

Compute the index for the value you are looking for and compare it with the stored column:

```python
needle = contacts.get_blind_index("email_idx", {"email": "alice@example.com"})
cursor.execute("SELECT * FROM contacts WHERE email_idx = %s", (needle,))
```

Blind indexes are deliberately short, so several different values can share one index value.
Always decrypt the rows you get back and check the plaintext before you trust a match.

## Decrypt

```python
assert contacts.decrypt_row(encrypted) == row
```

A wrong key, a tampered ciphertext or mismatched [AAD](guide/aad.md) raises
[`InvalidCiphertextException`][ciphersweet.InvalidCiphertextException].

## Next steps

- [Rows and field types](guide/encrypted-row.md) covers integers, floats, booleans, optional
  fields and JSON.
- [Blind indexes](guide/blind-indexes.md) explains fast and slow indexes, sizes, and compound
  indexes.
- [Compatibility with PHP](guide/compatibility.md) lists what must match when PHP and Python share
  data.
