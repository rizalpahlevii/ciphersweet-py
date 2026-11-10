"""ciphersweet-py: searchable field-level encryption, wire-compatible with
`paragonie/ciphersweet <https://github.com/paragonie/ciphersweet>`_ (PHP) and
`spatie/laravel-ciphersweet <https://github.com/spatie/laravel-ciphersweet>`_.
"""

from . import constants
from .aad import AAD
from .backend import Backend, BoringCrypto, FIPSCrypto, ModernCrypto
from .blind_index import BlindIndex, CompoundIndex, FastBlindIndex, FastCompoundIndex
from .encrypted_field import EncryptedField
from .encrypted_multi_rows import EncryptedMultiRows
from .encrypted_row import EncryptedRow
from .engine import CipherSweet
from .exceptions import (
    ArrayKeyException,
    BlindIndexNameCollisionException,
    BlindIndexNotFoundException,
    CipherSweetException,
    CryptoOperationException,
    EmptyFieldException,
    InvalidAADException,
    InvalidCiphertextException,
    JsonMapException,
    KeyProviderException,
)
from .json_field import EncryptedJsonField, JsonFieldMap
from .key import SymmetricKey
from .key_rotation import FieldRotator, MultiRowsRotator, RowRotator
from .keyprovider import (
    EnvProvider,
    FileProvider,
    KeyProvider,
    MultiTenantProvider,
    RandomProvider,
    StringProvider,
)
from .transformation import (
    AlphaCharactersOnly,
    AlphaNumericCharactersOnly,
    Compound,
    DigitsOnly,
    FirstCharacter,
    LastFourDigits,
    Lowercase,
)

__version__ = "0.2.0"

__all__ = [
    "AAD",
    "AlphaCharactersOnly",
    "AlphaNumericCharactersOnly",
    "ArrayKeyException",
    "Backend",
    "BlindIndex",
    "BlindIndexNameCollisionException",
    "BlindIndexNotFoundException",
    "BoringCrypto",
    "CipherSweet",
    "CipherSweetException",
    "Compound",
    "CompoundIndex",
    "CryptoOperationException",
    "DigitsOnly",
    "EmptyFieldException",
    "EncryptedField",
    "EncryptedJsonField",
    "EncryptedMultiRows",
    "EncryptedRow",
    "EnvProvider",
    "FIPSCrypto",
    "FastBlindIndex",
    "FastCompoundIndex",
    "FieldRotator",
    "FileProvider",
    "FirstCharacter",
    "InvalidAADException",
    "InvalidCiphertextException",
    "JsonFieldMap",
    "JsonMapException",
    "KeyProvider",
    "KeyProviderException",
    "LastFourDigits",
    "Lowercase",
    "ModernCrypto",
    "MultiRowsRotator",
    "MultiTenantProvider",
    "RandomProvider",
    "RowRotator",
    "StringProvider",
    "SymmetricKey",
    "constants",
]
