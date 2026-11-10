# ciphersweet-go

[ciphersweet-go](https://github.com/rizalpahlevii/ciphersweet-go) follows the PHP format for
`nacl:` ciphertexts and fast blind indexes, so the regular
[`ModernCrypto`][ciphersweet.ModernCrypto] reads its data. Two Go-only features need the
[`ciphersweet.compat.go`](../reference/go.md) module.

| Go feature | Python |
| --- | --- |
| `nacl:` ciphertexts, fast indexes | `ModernCrypto` |
| Slow (Argon2id) indexes, Go defaults of 512 MiB and 2 lanes | [`GoModernCrypto`][ciphersweet.compat.go.GoModernCrypto] |
| The `boring:` backend (AES-256-GCM, HKDF-SHA256) | [`GoBoringCrypto`][ciphersweet.compat.go.GoBoringCrypto] |

Go's `boring:` is a different format from PHP's `brng:`
[`BoringCrypto`][ciphersweet.BoringCrypto], despite the similar name.

```python
from ciphersweet import CipherSweet, StringProvider
from ciphersweet.compat.go import GoBoringCrypto, GoModernCrypto

engine = CipherSweet(StringProvider(key), GoModernCrypto())
boring_engine = CipherSweet(StringProvider(key), GoBoringCrypto())
```

The slow indexes need `argon2-cffi`:

```bash
pip install "ciphersweet-py[go]"
```

Slow indexes accept `time_cost`, `memory_cost_kib` and `parallelism` in `hash_config` to match a
non-default Go configuration.

## Typed values

ciphersweet-go's `EncryptedRow` stores booleans and numbers as text rather than CipherSweet's
typed encoding. Decrypt Go rows with text fields and convert the values yourself.

!!! warning
    This module mirrors the Go source, but it has not yet been tested against values produced
    by the Go library.
