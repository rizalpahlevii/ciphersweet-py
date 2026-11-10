# Blind indexes

A blind index is a keyed hash of a (possibly transformed) plaintext, truncated to a few bits.
Store it next to the ciphertext and search with `WHERE index_column = ?`.

```python
from ciphersweet import BlindIndex, Lowercase

BlindIndex("email_idx", [Lowercase()], 32, fast_hash=True)
#          name         transformations  bits  fast or slow
```

The name, transformations, bit length and fast/slow choice all change the output, so they must
match whatever wrote the stored values.

## Fast or slow

| | Fast | Slow (the default) |
| --- | --- | --- |
| `nacl:` / `brng:` | BLAKE2b | Argon2id |
| `fips:` | PBKDF2-SHA-384, 1 iteration | PBKDF2-SHA-384, many iterations |

A slow index makes brute-forcing low-entropy values (birth dates, last four digits) expensive
for someone who has the database but not the key. It also makes every write and search slower.
Most applications, Laravel's included, use fast indexes.

!!! note
    As in PHP, `BlindIndex(name)` on its own is **slow**. Pass `fast_hash=True`, or use
    [`FastBlindIndex`][ciphersweet.FastBlindIndex], for a fast one.

Slow indexes accept a `hash_config` (`opslimit`/`memlimit`, or `iterations` for FIPS). Values
below the defaults are ignored.

## Choosing a size

`filter_bits` sets the output length; the stored value is `ceil(bits / 8) * 2` hex characters.
Short indexes collide on purpose: many plaintexts share each value, which limits what the index
reveals, but a search returns some false positives. Decrypt the matches and compare the
plaintext. Larger indexes are more precise and reveal more. The
[CipherSweet documentation](https://ciphersweet.paragonie.com/) explains how to pick a size for
your data.

## Transformations

Transformations run in order before hashing. They let one index answer a looser question, such
as "same email ignoring case" or "same last four digits":

| Class | Output |
| --- | --- |
| [`Lowercase`][ciphersweet.Lowercase] | ASCII lowercase (like PHP `strtolower`) |
| [`AlphaCharactersOnly`][ciphersweet.AlphaCharactersOnly] | Only `A-Z` and `a-z` |
| [`AlphaNumericCharactersOnly`][ciphersweet.AlphaNumericCharactersOnly] | Only ASCII letters and digits |
| [`DigitsOnly`][ciphersweet.DigitsOnly] | Only `0-9` |
| [`FirstCharacter`][ciphersweet.FirstCharacter] | The first byte |
| [`LastFourDigits`][ciphersweet.LastFourDigits] | The last four digits, left-padded with `0` |
| [`Compound`][ciphersweet.Compound] | The default encoding for compound indexes |

Any callable that takes one value and returns `str` or `bytes` works as a custom transformation:

```python
def domain(value: bytes) -> bytes:
    return value.rsplit(b"@", 1)[-1]  # Lowercase() runs first and returns bytes

BlindIndex("email_domain", [Lowercase(), domain], 16, fast_hash=True)
```

A custom transformation must behave identically on the PHP side for the indexes to match.

## Compound indexes

A compound index hashes several columns together, for searches like "this last-four **and** VIP":

```python
from ciphersweet import LastFourDigits

idx = contacts.create_fast_compound_index("ssn_vip", ["ssn", "vip"], 32)
idx.add_transform("ssn", LastFourDigits())

needle = contacts.get_blind_index("ssn_vip", {"ssn": "6789", "vip": True})
```

`create_compound_index` makes a slow one. Use `add_row_transform` for a transformation that sees
the whole row.
