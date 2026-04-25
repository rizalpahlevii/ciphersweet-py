"""
EncryptedField: high-level interface for decrypting a CipherSweet-encrypted column.
"""

from .engine import CipherSweet


class EncryptedField:
    """
    Represents a single encrypted database column.

    Usage:
        field = EncryptedField(engine, table="users", field_name="email")
        plaintext = field.decrypt(ciphertext_from_db)

    Args:
        engine: A CipherSweet engine instance.
        table: The database table name (must match what was used during encryption).
        field_name: The column name (must match what was used during encryption).
    """

    def __init__(self, engine: CipherSweet, table: str, field_name: str):
        self._engine = engine
        self._table = table
        self._field_name = field_name

    def decrypt(self, ciphertext: str) -> str:
        """
        Decrypt an encrypted field value.

        Args:
            ciphertext: The raw ciphertext string stored in the database.

        Returns:
            The original plaintext string.
        """
        key = self._engine.get_field_symmetric_key(self._table, self._field_name)
        return self._engine.backend.decrypt(ciphertext, key)

