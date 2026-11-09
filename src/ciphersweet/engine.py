"""The ``CipherSweet`` engine: owns the key provider and backend and derives
per-column keys."""

from __future__ import annotations

from typing import Any, Dict, Mapping, Optional

from ._util import hkdf, hmac_sha256, pack, to_bytes
from .backend import Backend, BoringCrypto
from .constants import DS_BIDX, DS_EXT, DS_FENC
from .exceptions import CipherSweetException
from .key import SymmetricKey
from .keyprovider import KeyProvider, TenantId, is_multi_tenant_aware


class CipherSweet:
    """Entry point. Mirrors ``ParagonIE\\CipherSweet\\CipherSweet``.

    :param key_provider: where the root key comes from.
    :param backend: defaults to :class:`~ciphersweet.backend.BoringCrypto`,
        exactly like the PHP library.
    """

    def __init__(self, key_provider: KeyProvider, backend: Optional[Backend] = None) -> None:
        self.key_provider = key_provider
        self.backend: Backend = backend if backend is not None else BoringCrypto()
        self.multi_tenant_count_check = True

    def get_backend(self) -> Backend:
        return self.backend

    def get_key_provider(self) -> KeyProvider:
        return self.key_provider

    # -- key hierarchy ---------------------------------------------------

    def get_index_type_column(self, table_name: str, field_name: str, index_name: str) -> str:
        return self.backend.get_index_type_column(table_name, field_name, index_name)

    def get_blind_index_root_key(self, table_name: str, field_name: str) -> SymmetricKey:
        key = self.key_provider.get_symmetric_key()
        get_static = getattr(self.key_provider, "get_static_blind_index_tenant", None)
        if callable(get_static):
            tenant = get_static()
            if tenant is not None:
                key = self.key_provider.get_tenant(tenant).get_symmetric_key()  # type: ignore[attr-defined]
        return SymmetricKey(hkdf(key.get_raw_key(), to_bytes(table_name), DS_BIDX + to_bytes(field_name)))

    def get_blind_index_key(
        self,
        table_name: str,
        field_name: str,
        index_name: str,
        root_key: Optional[SymmetricKey] = None,
    ) -> SymmetricKey:
        """The per-index sub-key used by ``EncryptedField``/``EncryptedRow``:
        ``HMAC-SHA256(pack([table, field, index]), blind_index_root_key)``."""
        custom = getattr(self.backend, "derive_blind_index_key", None)
        if callable(custom):
            return custom(self.key_provider.get_symmetric_key(), table_name, field_name, index_name)
        if root_key is None:
            root_key = self.get_blind_index_root_key(table_name, field_name)
        return SymmetricKey(hmac_sha256(root_key.get_raw_key(), pack([table_name, field_name, index_name])))

    def get_field_symmetric_key(self, table_name: str, field_name: str) -> SymmetricKey:
        provider = (
            self.get_key_provider_for_active_tenant()
            if self.is_multi_tenant_supported()
            else self.key_provider
        )
        custom = getattr(self.backend, "derive_field_key", None)
        if callable(custom):
            return custom(provider.get_symmetric_key(), table_name, field_name)
        return SymmetricKey(
            hkdf(
                provider.get_symmetric_key().get_raw_key(),
                to_bytes(table_name),
                DS_FENC + to_bytes(field_name),
            )
        )

    def get_extension_key(self, extension_unique_name: str, *extra: str) -> SymmetricKey:
        info = DS_EXT + pack([extension_unique_name, *extra])
        provider = (
            self.get_key_provider_for_active_tenant()
            if self.is_multi_tenant_supported()
            else self.key_provider
        )
        return SymmetricKey(hkdf(provider.get_symmetric_key().get_raw_key(), b"", info))

    # -- multi-tenancy ---------------------------------------------------

    def _require_multi_tenant(self) -> Any:
        if not is_multi_tenant_aware(self.key_provider):
            raise CipherSweetException("Your Key Provider is not multi-tenant aware")
        return self.key_provider

    def get_key_provider_for_active_tenant(self) -> KeyProvider:
        return self._require_multi_tenant().get_active_tenant()

    def get_key_provider_for_tenant(self, name: TenantId) -> KeyProvider:
        return self._require_multi_tenant().get_tenant(name)

    def get_tenant_from_row(self, row: Mapping[str, Any], table_name: str = "") -> TenantId:
        return self._require_multi_tenant().get_tenant_from_row(row, table_name)

    def set_active_tenant(self, tenant: TenantId) -> None:
        self._require_multi_tenant().set_active_tenant(tenant)

    def inject_tenant_metadata(self, row: Dict[str, Any], table_name: str = "") -> Dict[str, Any]:
        if not is_multi_tenant_aware(self.key_provider):
            raise CipherSweetException("Multi-tenant is not supported")
        injected = self.key_provider.inject_tenant_metadata(row, table_name)  # type: ignore[attr-defined]
        if self.multi_tenant_count_check and len(injected) < len(row):
            raise CipherSweetException(
                "Injecting tenant metadata should not decrease the size of the array. "
                f"Before: {len(row)}. After: {len(injected)}."
            )
        return injected

    def is_multi_tenant_supported(self) -> bool:
        return bool(getattr(self.backend, "multi_tenant_safe", False)) and is_multi_tenant_aware(
            self.key_provider
        )

    def __repr__(self) -> str:
        return f"CipherSweet(backend={self.backend!r})"
