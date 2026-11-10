"""Key providers (``ParagonIE\\CipherSweet\\KeyProvider``)."""

from __future__ import annotations

import abc
import os
from typing import Any, Dict, Mapping, Optional, Union

from ._util import b64url_decode
from .exceptions import CipherSweetException, CryptoOperationException, KeyProviderException
from .key import SymmetricKey

TenantId = Union[str, int]


class KeyProvider(abc.ABC):
    """Supplies the root symmetric key to a :class:`~ciphersweet.CipherSweet` engine."""

    @abc.abstractmethod
    def get_symmetric_key(self) -> SymmetricKey:
        """Return the root key."""

    def __repr__(self) -> str:  # never leak key material
        return f"{type(self).__name__}(<redacted>)"


def decode_key(raw_key: Union[str, bytes, bytearray]) -> bytes:
    """Decode a key the way PHP's ``StringProvider`` does.

    * 64 characters: hex
    * 44 characters: base64url (padded)
    * 32 bytes: raw key bytes
    """
    if isinstance(raw_key, str):
        stripped = raw_key.strip()
        if len(stripped) == 64:
            try:
                return bytes.fromhex(stripped)
            except ValueError as exc:
                raise CryptoOperationException("Invalid hex key") from exc
        if len(stripped) == 44:
            try:
                return b64url_decode(stripped)
            except ValueError as exc:
                raise CryptoOperationException("Invalid base64url key") from exc
        raise CryptoOperationException(
            "Invalid key size: expected 64 hex characters, 44 base64url characters, or 32 raw bytes"
        )
    raw = bytes(raw_key)
    if len(raw) == 64:
        return decode_key(raw.decode("ascii"))
    if len(raw) == 44:
        return decode_key(raw.decode("ascii"))
    if len(raw) == 32:
        return raw
    raise CryptoOperationException("Invalid key size")


class StringProvider(KeyProvider):
    """A key given inline: 64 hex chars, 44 base64url chars, or 32 raw bytes.

    This is what Laravel's ``CIPHERSWEET_KEY`` holds (``php artisan
    ciphersweet:generate-key`` emits 64 hex characters).
    """

    def __init__(self, raw_key: Union[str, bytes]) -> None:
        self._key = decode_key(raw_key)

    def get_symmetric_key(self) -> SymmetricKey:
        return SymmetricKey(self._key)


class EnvProvider(KeyProvider):
    """Reads the key from an environment variable on every call.

    Accepts the same encodings as :class:`StringProvider`.
    """

    def __init__(self, var_name: str = "CIPHERSWEET_KEY") -> None:
        self.var_name = var_name

    def get_symmetric_key(self) -> SymmetricKey:
        value = os.environ.get(self.var_name)
        if not value:
            raise KeyProviderException(f"Environment variable {self.var_name} is not set")
        return SymmetricKey(decode_key(value))


class FileProvider(KeyProvider):
    """Reads the key from a file on every call.

    ``encoding="raw"`` (the default) matches PHP's ``FileProvider``: the file
    contents are used as the key bytes verbatim. Use ``encoding="auto"`` to
    accept a hex or base64url key file (surrounding whitespace is ignored),
    which is what Docker/Kubernetes secrets usually contain.
    """

    def __init__(self, path: Optional[Union[str, os.PathLike]] = None, encoding: str = "raw") -> None:
        if encoding not in ("raw", "auto"):
            raise ValueError("encoding must be 'raw' or 'auto'")
        self.path = path
        self.encoding = encoding

    def get_symmetric_key(self) -> SymmetricKey:
        if self.path is None:
            raise KeyProviderException("Symmetric key path was not provided")
        try:
            with open(self.path, "rb") as fh:
                contents = fh.read()
        except OSError as exc:
            raise KeyProviderException("Could not read symmetric key from file.") from exc
        if self.encoding == "auto":
            return SymmetricKey(decode_key(contents.strip()))
        return SymmetricKey(contents)


class RandomProvider(KeyProvider):
    """A random key generated once at construction. Data encrypted with it is
    lost when the process exits: use it for tests only."""

    def __init__(self, backend: Any = None) -> None:
        self._key = os.urandom(32)

    def get_symmetric_key(self) -> SymmetricKey:
        return SymmetricKey(self._key)

    def hex(self) -> str:
        return self._key.hex()


class MultiTenantProvider(KeyProvider):
    """Holds one key provider per tenant and an "active" tenant.

    Subclass it and override :meth:`get_tenant_from_row` and
    :meth:`inject_tenant_metadata` to pick the tenant from row data.
    """

    multi_tenant_aware = True

    def __init__(
        self, key_providers: Mapping[TenantId, KeyProvider], active: Optional[TenantId] = None
    ) -> None:
        self.tenants: Dict[TenantId, KeyProvider] = dict(key_providers)
        self.active = active

    def add_tenant(self, index: TenantId, provider: KeyProvider) -> MultiTenantProvider:
        self.tenants[index] = provider
        return self

    def set_active_tenant(self, index: TenantId) -> MultiTenantProvider:
        self.active = index
        return self

    def get_tenant(self, name: TenantId) -> KeyProvider:
        if name not in self.tenants:
            raise CipherSweetException("Tenant does not exist")
        return self.tenants[name]

    def get_active_tenant(self) -> KeyProvider:
        if self.active is None:
            raise CipherSweetException("Active tenant not set")
        if self.active not in self.tenants:
            raise CipherSweetException("Tenant does not exist")
        return self.tenants[self.active]

    def get_symmetric_key(self) -> SymmetricKey:
        return self.get_active_tenant().get_symmetric_key()

    def get_tenant_from_row(self, row: Mapping[str, Any], table_name: str) -> TenantId:
        if self.active is None:
            raise CipherSweetException("This is not implemented. Please override in a child class.")
        return self.active

    def inject_tenant_metadata(self, row: Dict[str, Any], table_name: str) -> Dict[str, Any]:
        return row


def is_multi_tenant_aware(provider: Any) -> bool:
    return bool(getattr(provider, "multi_tenant_aware", False))
