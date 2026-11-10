# ciphersweet-py

Searchable field-level encryption for Python, **wire-compatible with
[paragonie/ciphersweet](https://github.com/paragonie/ciphersweet)** (PHP) and therefore with
Laravel apps that use [spatie/laravel-ciphersweet](https://github.com/spatie/laravel-ciphersweet).

Data encrypted by PHP decrypts in Python and the other way round, and blind indexes computed in
Python match the ones PHP stored, so both sides can search the same database.

```bash
pip install ciphersweet-py
```

The import name is `ciphersweet`. Python 3.10 or newer is required.

## What it does

CipherSweet encrypts individual database columns and, next to each one, stores a short keyed
hash called a **blind index**. You search the encrypted column by hashing the value you are
looking for the same way and comparing it with the stored index, so the database never sees the
plaintext.

```python
from ciphersweet import BlindIndex, CipherSweet, EncryptedRow, Lowercase, ModernCrypto, StringProvider

engine = CipherSweet(StringProvider("4e1c44f87b4cdf21808762970b356891db180a9dd9850e7baf2a79ff3ab8a2fc"), ModernCrypto())

users = EncryptedRow(engine, "users").add_text_field("email")
users.add_blind_index("email", BlindIndex("email_idx", [Lowercase()], 32, fast_hash=True))

encrypted, indexes = users.prepare_row_for_storage({"id": 1, "email": "Alice@Example.com"})
needle = users.get_blind_index("email_idx", {"email": "alice@example.com"})
assert needle == indexes["email_idx"]
```

## Where to go next

<div class="grid cards" markdown>

- **[Getting started](getting-started.md)**: generate a key, encrypt a row, and search it.
- **[Compatibility with PHP](guide/compatibility.md)**: the settings that must match for both
  sides to read the same data.
- **[Laravel](guide/laravel.md)**: read and search data written by spatie/laravel-ciphersweet.
- **[API reference](reference/engine.md)**: every public class and function.

</div>

## Related projects

- [paragonie/ciphersweet](https://github.com/paragonie/ciphersweet), the PHP library this is a
  port of.
- [ciphersweet-go](https://github.com/rizalpahlevii/ciphersweet-go), the Go sibling. See
  [ciphersweet-go](guide/go.md) for how to read its data.
