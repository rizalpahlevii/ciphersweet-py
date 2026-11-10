# Single fields

[`EncryptedField`][ciphersweet.EncryptedField] encrypts one column of one table. Use it when only
one column needs protecting; for several columns, [`EncryptedRow`](encrypted-row.md) is simpler.

```python
from ciphersweet import BlindIndex, EncryptedField, LastFourDigits

ssn = EncryptedField(engine, "contacts", "ssn")
ssn.add_blind_index(BlindIndex("ssn_last4", [LastFourDigits()], 16, fast_hash=True))

ciphertext, indexes = ssn.prepare_for_storage("123-45-6789")
# indexes == {"ssn_last4": "..."}

ssn.decrypt_value(ciphertext)  # "123-45-6789"
```

The table and field names are part of key derivation, so they must match the PHP side exactly.

## Searching

```python
needle = ssn.get_blind_index("6789", "ssn_last4")
```

Note the argument order: the plaintext first, then the index name.

## Binary values

`EncryptedField` handles text. `decrypt_value` decodes the result as UTF-8; use
`decrypt_value_bytes` for binary data. For integers, floats and booleans, use
[`EncryptedRow`](encrypted-row.md), which encodes them the way PHP does.

## AAD

Pass AAD as the second argument to bind a ciphertext to another value, such as the row's id:

```python
ciphertext, indexes = ssn.prepare_for_storage("123-45-6789", "42")
ssn.decrypt_value(ciphertext, "42")
```

See [Additional authenticated data](aad.md).
