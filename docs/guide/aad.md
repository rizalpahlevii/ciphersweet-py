# Additional authenticated data

AAD binds a ciphertext to other values without encrypting them. Decryption only succeeds when the
same values are supplied again, which stops an attacker with write access from copying a
ciphertext into another row.

## Bind to another column

The simplest form names one column of the same row:

```python
from ciphersweet import EncryptedRow

messages = EncryptedRow(engine, "messages").add_text_field("body", "id")

encrypted = messages.encrypt_row({"id": 7, "body": "hi"})
messages.decrypt_row(encrypted)                # works
messages.decrypt_row({**encrypted, "id": 8})   # raises InvalidCiphertextException
```

## Several values

Use [`AAD`][ciphersweet.AAD] to combine columns and literal values:

```python
from ciphersweet import AAD

messages.add_text_field("subject", AAD(["id", "tenant_id"], ["v1"]))
```

Columns used as AAD must not themselves be encrypted fields;
[`InvalidAADException`][ciphersweet.InvalidAADException] is raised if they are.

## Single fields

[`EncryptedField`](encrypted-field.md) takes the AAD value directly:

```python
ciphertext = ssn.encrypt_value("123-45-6789", "42")
ssn.decrypt_value(ciphertext, "42")
```

## Compatibility

A single column name or literal uses PHP's legacy encoding (the raw value). Several values use
the canonical length-prefixed encoding. Both match PHP, provided the same columns and literals
are used on both sides.
