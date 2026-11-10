# Backends

A backend decides which algorithms are used. Every ciphertext starts with the backend's prefix,
so you can tell from stored data which one wrote it.

| Class | Prefix | Algorithms | Notes |
| --- | --- | --- | --- |
| [`BoringCrypto`][ciphersweet.BoringCrypto] | `brng:` | XChaCha20 + BLAKE2b-MAC, Argon2id | PHP's default when no backend is given; multi-tenant safe |
| [`ModernCrypto`][ciphersweet.ModernCrypto] | `nacl:` | XChaCha20-Poly1305, BLAKE2b, Argon2id | Laravel's default (`CIPHERSWEET_BACKEND=nacl`) |
| [`FIPSCrypto`][ciphersweet.FIPSCrypto] | `fips:` | AES-256-CTR + HMAC-SHA-384, PBKDF2-SHA-384 | FIPS-approved primitives; multi-tenant safe |

```python
from ciphersweet import BoringCrypto, CipherSweet, FIPSCrypto, ModernCrypto

CipherSweet(provider)                  # BoringCrypto, same as PHP
CipherSweet(provider, ModernCrypto())  # nacl:
CipherSweet(provider, FIPSCrypto())    # fips:
```

## Choosing one

- **Sharing data with an existing app?** Use whatever it uses. Look at the prefix of a stored
  ciphertext.
- **Laravel?** `ModernCrypto`, unless `CIPHERSWEET_BACKEND` says otherwise.
- **Need FIPS-approved algorithms?** `FIPSCrypto`.
- **Starting fresh, or need [multi-tenancy](multi-tenancy.md)?** `BoringCrypto`.

Backends are stateless, so one instance can be shared between engines and threads.

Switching backends later means re-encrypting your data; see [Key rotation](key-rotation.md).

For the Go-only `boring:` format, see [ciphersweet-go](go.md).
