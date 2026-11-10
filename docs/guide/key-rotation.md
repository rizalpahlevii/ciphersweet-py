# Key rotation

To change the key or the backend, decrypt with the old configuration and encrypt with the new
one. The rotators do that and tell you which values still need it.

```python
from ciphersweet import CipherSweet, EncryptedField, FieldRotator, ModernCrypto, StringProvider

old_engine = CipherSweet(StringProvider(old_key), ModernCrypto())
new_engine = CipherSweet(StringProvider(new_key), ModernCrypto())

old_field = EncryptedField(old_engine, "contacts", "ssn")
new_field = EncryptedField(new_engine, "contacts", "ssn")
rotator = FieldRotator(old_field, new_field)

if rotator.needs_re_encrypt(ciphertext):
    ciphertext, indexes = rotator.prepare_for_update(ciphertext)
```

`needs_re_encrypt` returns `True` when the value has a different backend prefix or does not
decrypt with the new key.

| Rotator | Works on | `prepare_for_update` returns |
| --- | --- | --- |
| [`FieldRotator`][ciphersweet.FieldRotator] | One ciphertext | `(ciphertext, indexes)` |
| [`RowRotator`][ciphersweet.RowRotator] | One row (a dict) | `(row, indexes)` |
| [`MultiRowsRotator`][ciphersweet.MultiRowsRotator] | `{table: row}` | `(rows, indexes)` |

Remember to write the new blind indexes too: they depend on the key.

A typical migration loops over the table in batches, rotates each row that needs it, and keeps
both keys available until it finishes, so the application can read old and new rows meanwhile.

For a column exported to a file, `ciphersweet rotate` does the same from the shell: see
[Command-line tool](cli.md#rotating-keys).
