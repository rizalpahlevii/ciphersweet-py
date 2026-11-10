"""Constants shared with ``ParagonIE\\CipherSweet\\Constants``."""

DS_BIDX = b"\x7e" * 32
"""Domain separation prefix for blind index root keys."""

DS_FENC = b"\xb4" * 32
"""Domain separation prefix for field encryption keys."""

DS_JSON = bytes.fromhex("d9a736ff8eb9d8cc6dd2f91a6e55e78e44433736573b4eda34bb234609c8b6a5")
"""Domain separation prefix for encrypted JSON sub-keys."""

DS_EXT = bytes.fromhex("8414863006d7a16a5066e4da325ec56f165327504d2ede2fcf5e8f3aa9057bed")
"""Domain separation prefix for extension keys."""

TYPE_JSON = "json"
TYPE_BOOLEAN = "bool"
TYPE_TEXT = "string"
TYPE_INT = "int"
TYPE_FLOAT = "float"

TYPE_OPTIONAL_JSON = "?json"
TYPE_OPTIONAL_BOOLEAN = "?bool"
TYPE_OPTIONAL_TEXT = "?string"
TYPE_OPTIONAL_INT = "?int"
TYPE_OPTIONAL_FLOAT = "?float"

TYPES_OPTIONAL = (
    TYPE_OPTIONAL_JSON,
    TYPE_OPTIONAL_BOOLEAN,
    TYPE_OPTIONAL_TEXT,
    TYPE_OPTIONAL_INT,
    TYPE_OPTIONAL_FLOAT,
)
TYPES_BOOLEAN = (TYPE_OPTIONAL_BOOLEAN, TYPE_BOOLEAN)
TYPES_JSON = (TYPE_OPTIONAL_JSON, TYPE_JSON)

COMPOUND_SPECIAL = "special__compound__indexes"
FILE_TABLE = "special__file__encryption"
FILE_COLUMN = "special__file__ciphersweet"
DUMMY_SALT = b"\x00" * 16
