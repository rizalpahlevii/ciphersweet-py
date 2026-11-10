# Key providers

A key provider gives the engine its 256-bit root key.

| Provider | Key source |
| --- | --- |
| [`StringProvider(key)`][ciphersweet.StringProvider] | 64 hex chars, 44 base64url chars, or 32 raw bytes |
| [`EnvProvider("CIPHERSWEET_KEY")`][ciphersweet.EnvProvider] | An environment variable, read on each use |
| [`FileProvider(path)`][ciphersweet.FileProvider] | File contents as raw bytes (PHP behaviour); `encoding="auto"` accepts hex or base64url |
| [`RandomProvider()`][ciphersweet.RandomProvider] | A random key, for tests only |
| [`MultiTenantProvider({...})`][ciphersweet.MultiTenantProvider] | One provider per tenant; see [Multi-tenancy](multi-tenancy.md) |

## Inline or from the environment

```python
from ciphersweet import CipherSweet, EnvProvider, StringProvider

engine = CipherSweet(StringProvider("4e1c44f87b4cdf21808762970b356891db180a9dd9850e7baf2a79ff3ab8a2fc"))
engine = CipherSweet(EnvProvider())  # reads CIPHERSWEET_KEY
```

`EnvProvider` reads the variable every time a key is needed, so a missing variable fails when
you first encrypt or decrypt, not when you build the engine.

## From a file

PHP's `FileProvider` uses the file's bytes as the key, so the file must hold exactly 32 raw
bytes. Docker and Kubernetes secrets usually hold a hex string with a trailing newline instead;
pass `encoding="auto"` for those:

```python
from ciphersweet import FileProvider

FileProvider("/run/secrets/ciphersweet_key", encoding="auto")
```

## Writing your own

Subclass [`KeyProvider`][ciphersweet.KeyProvider] and return a
[`SymmetricKey`][ciphersweet.SymmetricKey]:

```python
from ciphersweet import KeyProvider, SymmetricKey
from ciphersweet.keyprovider import decode_key

class VaultProvider(KeyProvider):
    def __init__(self, client):
        self.client = client

    def get_symmetric_key(self) -> SymmetricKey:
        return SymmetricKey(decode_key(self.client.read("ciphersweet")))
```

Providers never print their key: `repr()` shows `<redacted>`.
