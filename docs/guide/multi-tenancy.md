# Multi-tenancy

With [`MultiTenantProvider`][ciphersweet.MultiTenantProvider], each tenant has its own key and
the engine picks the right one per row. Only backends marked multi-tenant safe support this:
[`BoringCrypto`][ciphersweet.BoringCrypto] and [`FIPSCrypto`][ciphersweet.FIPSCrypto].

```python
from ciphersweet import BoringCrypto, CipherSweet, MultiTenantProvider, StringProvider

provider = MultiTenantProvider(
    {
        "acme": StringProvider(acme_key),
        "globex": StringProvider(globex_key),
    },
    active="acme",
)
engine = CipherSweet(provider, BoringCrypto())
```

## Picking the tenant from the row

Out of the box, every row uses the active tenant. To store and read the tenant with each row,
subclass the provider:

```python
class TenantFromRow(MultiTenantProvider):
    def get_tenant_from_row(self, row, table_name):
        return row["tenant"]

    def inject_tenant_metadata(self, row, table_name):
        return {**row, "tenant": self.active}
```

`encrypt_row` calls `inject_tenant_metadata` after encrypting, and `decrypt_row` calls
`get_tenant_from_row` and switches the active tenant before decrypting. Switch tenants yourself
with `engine.set_active_tenant("globex")`, or `field.set_active_tenant(...)` on an
[`EncryptedField`](encrypted-field.md).
