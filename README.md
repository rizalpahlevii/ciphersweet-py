# ciphersweet-python

A Python library to **decrypt** [CipherSweet](https://github.com/paragonie/ciphersweet)-encrypted database fields.

Compatible with:
- **PHP**: [paragonie/ciphersweet](https://github.com/paragonie/ciphersweet)
- **Go**: [rizalpahlevii/ciphersweet-go](https://github.com/rizalpahlevii/ciphersweet-go)
- **Laravel**: [magentron/ciphersweet-for-laravel](https://github.com/magentron/ciphersweet-for-laravel)

> ⚠️ This library is **decrypt-only** by design. It does not include ORM integration.

---

## Installation

```bash
pip install ciphersweet-python
```

**Dependencies:** `cryptography`, `PyNaCl`

---

## Quick Start

```python
from ciphersweet import CipherSweet, NaClBackend, StringKeyProvider, EncryptedField

# 1. Set up the engine (NaCl is the default used by the Go library)
engine = CipherSweet(
    backend=NaClBackend(),
    key_provider=StringKeyProvider("your-64-hex-char-master-key-here"),
)

# 2. Define an encrypted field (table + column must match what was used during encryption)
email_field = EncryptedField(engine, table="users", field_name="email")

# 3. Decrypt a ciphertext retrieved from the database
ciphertext = "nacl:..."  # value from your DB column
plaintext = email_field.decrypt(ciphertext)
print(plaintext)  # alice@example.com
```

---

## Backends

### NaCl (ModernCrypto) — `NaClBackend`
- **Algorithm:** XChaCha20-Poly1305 via libsodium / PyNaCl
- **Ciphertext prefix:** `nacl:`
- **Used by:** `rizalpahlevii/ciphersweet-go` by default

### FIPS (FIPSCrypto) — `FIPSBackend`
- **Algorithm:** AES-256-CTR + HMAC-SHA384 (Encrypt-then-MAC)
- **Ciphertext prefix:** `fips:`

---

## Key Providers

Your master key must be a 256-bit value as a 64-character hex string.
Generate one with: `openssl rand -hex 32`

```python
from ciphersweet import StringKeyProvider, EnvKeyProvider, FileKeyProvider

StringKeyProvider("a1b2...64hexchars")    # inline hex key
EnvKeyProvider()                           # reads CIPHERSWEET_KEY env var
EnvKeyProvider("MY_VAR")                  # reads custom env var
FileKeyProvider("/run/secrets/key")       # reads hex key from file
```

---

## Decrypting Multiple Fields

```python
engine = CipherSweet(NaClBackend(), EnvKeyProvider())

email_field = EncryptedField(engine, table="users", field_name="email")
phone_field = EncryptedField(engine, table="users", field_name="phone")

row = fetch_row_from_db(user_id=42)
email = email_field.decrypt(row["email"])
phone = phone_field.decrypt(row["phone"])
```

> The `table` and `field_name` must exactly match what was used during encryption.

---

## License

MIT
