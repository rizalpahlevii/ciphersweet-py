# Database columns

Ciphertexts are base64url text, so a `TEXT` column works in every database. A blind index of
`n` bits is `ceil(n / 8) * 2` hex characters; [`index_width`][ciphersweet.migrate.index_width]
computes it.

[`ciphersweet.migrate.Plan`][ciphersweet.migrate.Plan] writes the DDL for you:

```python
from ciphersweet.migrate import Dialect, Plan

plan = (
    Plan("users", Dialect.POSTGRESQL)
    .add_encrypted_column("email")
    .add_index_column("email_idx", 32)
)
print(plan.up())            # ALTER TABLE ... ADD COLUMN ..., CREATE INDEX ...
print(plan.down())          # the reverse
print(plan.create_table())  # a new table with an id column
```

Dialects are `MYSQL` (the default), `POSTGRESQL` and `SQLITE`. Identifiers are checked against
`[A-Za-z_][A-Za-z0-9_]*`, and anything else raises `ValueError`.

For Laravel's shared index table, see
[`laravel_blind_indexes_table`][ciphersweet.migrate.laravel_blind_indexes_table].
