# Encrypted JSON

A JSON field encrypts selected paths inside a document and leaves the rest readable. Each path
is encrypted under its own derived key.

```python
from ciphersweet import EncryptedRow, JsonFieldMap

profile_map = (
    JsonFieldMap()
    .add_text_field(["address", "street"])
    .add_integer_field("age")
)
users = EncryptedRow(engine, "users").add_json_field("profile", profile_map)

encrypted = users.encrypt_row(
    {"id": 1, "profile": {"address": {"street": "1 Main St", "city": "Oslo"}, "age": 41}}
)
# encrypted["profile"] is a JSON string; "city" is still plaintext
users.decrypt_row(encrypted)["profile"]["age"]  # 41
```

A path is a list of keys (strings) and list positions (integers). A single key can be passed as a
plain string.

## Strict mode

By default (`strict=True`) every mapped path must be present in the document. Pass
`strict=False` to `add_json_field` to skip missing paths instead. Use `add_optional_json_field`
when the whole column may be `None`.

## Reusing maps

`add_map_field_from_template(root, template)` copies another map's paths under a prefix, which
helps when the same structure appears in several places. A map can be saved with
`to_string()` and loaded with `JsonFieldMap.from_string()`; the string carries a checksum and
is compatible with PHP's.

## Without a row

[`EncryptedJsonField`][ciphersweet.EncryptedJsonField] works on a single JSON column:

```python
from ciphersweet import EncryptedJsonField

field = EncryptedJsonField.create(engine, profile_map, "users", "profile")
encoded = field.encrypt_json({"address": {"street": "1 Main St"}, "age": 41})
field.decrypt_json(encoded)
```
