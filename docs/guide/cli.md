# Command-line tool

Installing the package also installs a `ciphersweet` command (`python -m ciphersweet` works too):

```bash
export CIPHERSWEET_KEY=$(ciphersweet generate-key)   # 64 hex chars; --base64 for base64url

ciphersweet encrypt --table users --column email "alice@example.com"
# nacl:...
ciphersweet decrypt --table users --column email "nacl:..."
# alice@example.com

# the value to search for, as stored by BlindIndex("email_index", [Lowercase()], 32, fast_hash=True)
ciphersweet blind-index --table users --column email --name email_index \
    --bits 32 --fast --transform lowercase "Alice@Example.com"
```

* The key comes from `CIPHERSWEET_KEY` by default. Use `--key-env VAR`, `--key-file PATH` (hex or
  base64url) or `--key KEY` instead; `--key` is visible to other users in the process list.
* The backend comes from `--backend nacl|boring|fips`, then `CIPHERSWEET_BACKEND`, then `nacl`
  (Laravel's default). `decrypt` reads it from the ciphertext prefix when `--backend` is omitted.
* `--table` and `--column` are part of the key derivation, so they must match the PHP side.
  `--aad` binds the value to extra data such as the row id.
* Without a value argument (or with `-`), the value is read from stdin, minus one trailing newline.
  `decrypt` writes the plaintext as raw bytes followed by a newline.
* `blind-index` defaults to a slow 256-bit index, as PHP does. `--transform` can be repeated:
  `lowercase`, `alpha`, `alphanumeric`, `digits`, `first-character`, `last-four-digits`.
  `--typed` also prints the index type column value.

## Rotating keys

`rotate` re-encrypts one ciphertext per line from stdin to stdout, for example after exporting a
column:

```bash
CIPHERSWEET_OLD_KEY=<old key> CIPHERSWEET_KEY=<new key> \
    ciphersweet rotate --table users --column email < old.txt > new.txt
# rotated 120, already current 3
```

The old key comes from `CIPHERSWEET_OLD_KEY` (or `--old-key-env`/`--old-key-file`/`--old-key`), the
new one from `CIPHERSWEET_KEY` (or the `--new-key-*` options). Pass `--new-backend` to move to
another backend; the old backend is read from each prefix unless `--old-backend` is given. Output
lines stay in input order, blank lines and values that are already current pass through
unchanged, and nothing is written if any line fails to decrypt. Recompute blind indexes for the
new key separately.

## Exit status

The exit status is 0 on success, 1 when a key or ciphertext is rejected and 2 on a usage error.

Run `ciphersweet COMMAND --help` for every option. For rotation from Python code, see
[Key rotation](key-rotation.md).
