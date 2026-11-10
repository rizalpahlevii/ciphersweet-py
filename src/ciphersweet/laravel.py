"""Helpers for sharing data with Laravel apps that use
`spatie/laravel-ciphersweet <https://github.com/spatie/laravel-ciphersweet>`_.

The crypto is plain CipherSweet, so the main things to get right are the
configuration (``CIPHERSWEET_*`` environment variables), the table name used
for key derivation (the model's ``getTable()``), and the shared
``blind_indexes`` table that the package keeps its indexes in.

Example::

    from ciphersweet import BlindIndex, EncryptedRow, LastFourDigits
    from ciphersweet.laravel import engine_from_env, blind_index_records

    engine = engine_from_env()             # reads CIPHERSWEET_BACKEND / _KEY
    users = EncryptedRow(engine, "users")  # same as the model's table
    users.add_text_field("email")
    users.add_blind_index("email", BlindIndex("email_index", fast_hash=True))

    row = users.decrypt_row(db_row)
"""

from __future__ import annotations

import os
import secrets
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple, Union

from ._util import b64url_encode
from .backend import Backend, BoringCrypto, FIPSCrypto, ModernCrypto
from .encrypted_row import EncryptedRow
from .engine import CipherSweet
from .exceptions import CipherSweetException
from .keyprovider import FileProvider, KeyProvider, RandomProvider, StringProvider

BLIND_INDEXES_TABLE = "blind_indexes"

BACKENDS: Dict[str, Callable[[], Backend]] = {
    "nacl": ModernCrypto,
    "boring": BoringCrypto,
    "fips": FIPSCrypto,
}


def backend_from_name(name: str) -> Backend:
    """Map Laravel's ``ciphersweet.backend`` value to a backend instance."""
    try:
        return BACKENDS[name.lower()]()
    except KeyError:
        raise CipherSweetException(
            f"Unknown CipherSweet backend {name!r}; expected one of {sorted(BACKENDS)}"
        ) from None


def engine_from_env(env: Optional[Mapping[str, str]] = None) -> CipherSweet:
    """Build an engine from the same environment variables Laravel reads.

    * ``CIPHERSWEET_BACKEND``: ``nacl`` (default), ``boring`` or ``fips``
    * ``CIPHERSWEET_PROVIDER``: ``string`` (default), ``file`` or ``random``
    * ``CIPHERSWEET_KEY``: the key for the ``string`` provider
    * ``CIPHERSWEET_FILE_PATH``: the key file for the ``file`` provider
    """
    env = os.environ if env is None else env
    backend = backend_from_name(env.get("CIPHERSWEET_BACKEND") or "nacl")
    provider_name = (env.get("CIPHERSWEET_PROVIDER") or "string").lower()
    provider: KeyProvider
    if provider_name == "string":
        key = env.get("CIPHERSWEET_KEY")
        if not key:
            raise CipherSweetException("CIPHERSWEET_KEY is not set")
        provider = StringProvider(key)
    elif provider_name == "file":
        provider = FileProvider(env.get("CIPHERSWEET_FILE_PATH"))
    else:
        provider = RandomProvider(backend)
    return CipherSweet(provider, backend)


def generate_key(base64: bool = False) -> str:
    """Same output as ``php artisan ciphersweet:generate-key`` (hex by default)."""
    raw = secrets.token_bytes(32)
    return b64url_encode(raw) if base64 else raw.hex()


def permit_empty_from_env(env: Optional[Mapping[str, str]] = None) -> bool:
    env = os.environ if env is None else env
    return (env.get("CIPHERSWEET_PERMIT_EMPTY") or "").lower() in ("1", "true", "on", "yes")


def blind_index_records(
    encrypted_row: EncryptedRow,
    attributes: Mapping[str, Any],
    indexable_type: str,
    indexable_id: Union[int, str],
) -> List[Dict[str, Any]]:
    """Rows to upsert into ``blind_indexes`` for one model, exactly as
    ``UsesCipherSweet::updateBlindIndexes`` writes them.

    ``indexable_type`` is the model's morph class (by default the fully
    qualified PHP class name, e.g. ``"App\\\\Models\\\\User"``).
    """
    return [
        {
            "indexable_type": indexable_type,
            "indexable_id": indexable_id,
            "name": name,
            "value": value,
        }
        for name, value in encrypted_row.get_all_blind_indexes(attributes).items()
    ]


def blind_index_value(
    encrypted_row: EncryptedRow, column: str, index_name: str, value: Any
) -> Union[str, Dict[str, str]]:
    """The value ``whereBlind($column, $indexName, $value)`` searches for."""
    return encrypted_row.get_blind_index(index_name, {column: value})


def where_blind_sql(
    model_table: str,
    key_name: str,
    indexable_type: str,
    encrypted_row: EncryptedRow,
    column: str,
    index_name: str,
    value: Any,
    placeholder: str = "%s",
) -> Tuple[str, List[Any]]:
    """An ``EXISTS (...)`` condition equivalent to Laravel's ``whereBlind``.

    Returns ``(sql, params)``; use ``placeholder="?"`` for sqlite3.
    Identifiers are not quoted or escaped: pass trusted names only.
    """
    p = placeholder
    sql = (
        f"EXISTS (SELECT 1 FROM {BLIND_INDEXES_TABLE} "
        f"WHERE indexable_type = {p} AND indexable_id = {model_table}.{key_name} "
        f"AND name = {p} AND value = {p})"
    )
    return sql, [indexable_type, index_name, blind_index_value(encrypted_row, column, index_name, value)]
