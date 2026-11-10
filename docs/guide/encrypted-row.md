# Rows and field types

[`EncryptedRow`][ciphersweet.EncryptedRow] describes the encrypted columns of one table. It is
what spatie/laravel-ciphersweet builds for each model.

```python
from ciphersweet import EncryptedRow

users = (
    EncryptedRow(engine, "users")
    .add_text_field("email")
    .add_integer_field("birth_year")
    .add_float_field("balance")
    .add_boolean_field("vip")
    .add_optional_text_field("nickname")
)

encrypted = users.encrypt_row(
    {"id": 1, "email": "a@example.com", "birth_year": 1990, "balance": 12.5, "vip": False, "nickname": None}
)
decrypted = users.decrypt_row(encrypted)
```

Every `add_*` method returns the row, so calls can be chained. Columns you did not register pass
through untouched.

## Field types

| Method | PHP constant | Python value |
| --- | --- | --- |
| `add_text_field` | `TYPE_TEXT` | `str` (or `bytes`) |
| `add_integer_field` | `TYPE_INT` | `int` (signed 64-bit) |
| `add_float_field` | `TYPE_FLOAT` | `float` |
| `add_boolean_field` | `TYPE_BOOLEAN` | `bool` or `None` |
| `add_json_field` | `TYPE_JSON` | `dict` or `list`, with a [`JsonFieldMap`](json.md) |
| `add_optional_*_field` | `TYPE_OPTIONAL_*` | as above; `None` is stored unencrypted |

A few details worth knowing:

- Integers are stored as 8 bytes, not as decimal text, so PHP and Python must both treat the
  column as an integer.
- Booleans can be `None`: a null boolean is still encrypted, so it cannot be told apart from
  `True` or `False` in the database.
- In an optional field, `None` is left as `None` and is visible in the database.
- `Enum` members are stored as their value.
- Text that is not valid UTF-8 decrypts to `bytes`.

## Storing and searching

[`prepare_row_for_storage`][ciphersweet.EncryptedRow.prepare_row_for_storage] returns the
encrypted row and its blind indexes in one call:

```python
from ciphersweet import BlindIndex, Lowercase

users.add_blind_index("email", BlindIndex("email_idx", [Lowercase()], 32, fast_hash=True))

encrypted, indexes = users.prepare_row_for_storage(row)
needle = users.get_blind_index("email_idx", {"email": "A@example.com"})
```

`get_blind_index` takes a dictionary because [compound indexes](blind-indexes.md#compound-indexes)
read several columns. Pass only the columns the index needs.

## Missing and empty columns

`encrypt_row` raises [`ArrayKeyException`][ciphersweet.ArrayKeyException] when a registered
column is missing from the row. `decrypt_row` raises
[`EmptyFieldException`][ciphersweet.EmptyFieldException] instead, unless you allow it:

```python
users.set_permit_empty(True)  # skip registered columns that are not in the row
```

This is useful when you `SELECT` only some columns. Laravel sets the same option from
`CIPHERSWEET_PERMIT_EMPTY`.

## Typed indexes

By default an index value is a hex string. With typed indexes it is a dictionary holding the
value and a short type identifier, matching PHP's `setTypedIndexes(true)`:

```python
users = EncryptedRow(engine, "users", use_typed_indexes=True)
# indexes == {"email_idx": {"type": "...", "value": "..."}}
```

## Binding to the primary key

Pass `primary_key_column_name` and register fields with `auto_bind_context=True` to bind each
ciphertext to its row's primary key automatically:

```python
from ciphersweet import constants

users = EncryptedRow(engine, "users", primary_key_column_name="id")
users.add_field("email", constants.TYPE_TEXT, auto_bind_context=True)
```

A ciphertext copied to another row then fails to decrypt. See
[Additional authenticated data](aad.md) for the general mechanism.
