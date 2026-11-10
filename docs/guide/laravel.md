# Laravel

[spatie/laravel-ciphersweet](https://github.com/spatie/laravel-ciphersweet) is plain CipherSweet
underneath, so a Python service can read, write and search the same tables. The
[`ciphersweet.laravel`](../reference/laravel.md) module covers the parts that are specific to the
package: its configuration and its shared `blind_indexes` table.

## Engine from the same environment

```python
from ciphersweet.laravel import engine_from_env

engine = engine_from_env()
```

This reads the variables Laravel reads:

| Variable | Values |
| --- | --- |
| `CIPHERSWEET_BACKEND` | `nacl` (default), `boring` or `fips` |
| `CIPHERSWEET_PROVIDER` | `string` (default), `file` or `random` |
| `CIPHERSWEET_KEY` | The key, for the `string` provider |
| `CIPHERSWEET_FILE_PATH` | The key file, for the `file` provider |

Pass a dictionary to `engine_from_env(env)` to read somewhere other than `os.environ`.
`permit_empty_from_env()` reads `CIPHERSWEET_PERMIT_EMPTY`.

## Mirror the model

Use the model's table name (`$model->getTable()`) and repeat what its `configureCipherSweet()`
method does:

```php
// app/Models/User.php
public static function configureCipherSweet(EncryptedRow $encryptedRow): void
{
    $encryptedRow
        ->addField('email')
        ->addBlindIndex('email', new BlindIndex('email_index'));
}
```

```python
from ciphersweet import BlindIndex, EncryptedRow

users = EncryptedRow(engine, "users")
users.add_text_field("email")
users.add_blind_index("email", BlindIndex("email_index"))  # slow, like `new BlindIndex('email_index')`

user = users.decrypt_row(db_row)
```

!!! note
    `new BlindIndex('email_index')` in PHP is a slow index. If the model passes `true` as the
    fourth argument (`new BlindIndex('email_index', [], 256, true)`), use `fast_hash=True`.

## The `blind_indexes` table

The package stores indexes in one shared table rather than in columns on the model's table.
[`blind_index_records`][ciphersweet.laravel.blind_index_records] returns the rows that
`updateBlindIndexes()` would write:

```python
from ciphersweet.laravel import blind_index_records

records = blind_index_records(users, user, "App\\Models\\User", user["id"])
# [{"indexable_type": "App\\Models\\User", "indexable_id": 1, "name": "email_index", "value": "..."}]
```

Upsert them on `(indexable_type, indexable_id, name)`. The type is the model's morph class,
which is the fully qualified class name unless you defined a morph map.

## Searching like `whereBlind`

[`where_blind_sql`][ciphersweet.laravel.where_blind_sql] builds the same `EXISTS` condition as
`User::whereBlind('email', 'email_index', $email)`:

```python
from ciphersweet.laravel import where_blind_sql

condition, params = where_blind_sql(
    "users", "id", "App\\Models\\User", users, "email", "email_index", "alice@example.com"
)
cursor.execute(f"SELECT * FROM users WHERE {condition}", params)
```

The default placeholder is `%s`; pass `placeholder="?"` for `sqlite3`. Table and column names
are inserted as they are, so pass only trusted names.

To create the table outside Laravel,
[`laravel_blind_indexes_table()`][ciphersweet.migrate.laravel_blind_indexes_table] returns the
equivalent DDL.

## Keys

[`generate_key()`][ciphersweet.laravel.generate_key] returns a key in the format of
`php artisan ciphersweet:generate-key` (hex, or base64url with `base64=True`).
