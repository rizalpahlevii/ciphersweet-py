# Changelog

## 0.1.0 (unreleased)

First full release. Replaces the earlier decrypt-only prototype.

- Backends: `ModernCrypto` (`nacl:`), `BoringCrypto` (`brng:`, the PHP default) and
  `FIPSCrypto` (`fips:`), wire-compatible with paragonie/ciphersweet v4.
- `CipherSweet` engine with the PHP key hierarchy, extension keys and multi-tenant support.
- `EncryptedField`, `EncryptedRow`, `EncryptedMultiRows`, `EncryptedJsonField`/`JsonFieldMap`.
- Typed fields (`string`, `int`, `float`, `bool`, `json` and their optional variants), AAD.
- Blind indexes (fast and slow), compound indexes, all upstream transformations.
- Key providers: string, env, file, random, multi-tenant. Key rotation helpers.
- `ciphersweet.laravel`: engine from `CIPHERSWEET_*` env vars and `blind_indexes` table helpers
  for spatie/laravel-ciphersweet.
- `ciphersweet.compat.go`: reads ciphersweet-go's `boring:` format and Go-style slow indexes.
- `ciphersweet.migrate`: DDL helpers.
- Fixed in the prototype: FIPS MAC key length (48 → 32 bytes, as in PHP).
