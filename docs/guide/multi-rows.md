# Several tables at once

[`EncryptedMultiRows`][ciphersweet.EncryptedMultiRows] holds one
[`EncryptedRow`](encrypted-row.md) per table, so related rows can be encrypted in one call. Every
method takes the table name first.

```python
from ciphersweet import BlindIndex, EncryptedMultiRows

rows = (
    EncryptedMultiRows(engine)
    .add_text_field("users", "email")
    .add_text_field("orders", "shipping_address")
)
rows.add_blind_index("users", "email", BlindIndex("email_idx", fast_hash=True))

encrypted, indexes = rows.prepare_for_storage(
    {
        "users": {"id": 1, "email": "a@example.com"},
        "orders": {"id": 10, "shipping_address": "1 Main St"},
    }
)
# indexes == {"users": {"email_idx": "..."}, "orders": {}}

rows.decrypt_many_rows(encrypted)
```

Tables missing from the input are skipped. To get at one table's
[`EncryptedRow`][ciphersweet.EncryptedRow], call `get_encrypted_row_object_for_table("users")`.

`EncryptedMultiRows(engine, auto_bind_context=True)` together with
`set_primary_key_column_name(table, column)` binds each table's fields to its primary key, as
described in [Rows and field types](encrypted-row.md#binding-to-the-primary-key).
