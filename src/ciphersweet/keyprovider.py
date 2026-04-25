"""Key providers for CipherSweet."""

import os


class StringKeyProvider:
    """Provide a key from a hex string (e.g. from openssl rand -hex 32)."""

    def __init__(self, hex_key: str):
        raw = bytes.fromhex(hex_key)
        if len(raw) != 32:
            raise ValueError("Key must be exactly 32 bytes (64 hex characters).")
        self._key = raw

    def get_symmetric_key(self) -> bytes:
        return self._key


class EnvKeyProvider:
    """Provide a key from an environment variable (hex-encoded)."""

    def __init__(self, env_var: str = "CIPHERSWEET_KEY"):
        self._env_var = env_var

    def get_symmetric_key(self) -> bytes:
        hex_key = os.environ.get(self._env_var)
        if not hex_key:
            raise RuntimeError(f"Environment variable '{self._env_var}' is not set.")
        raw = bytes.fromhex(hex_key)
        if len(raw) != 32:
            raise ValueError("Key must be exactly 32 bytes (64 hex characters).")
        return raw


class FileKeyProvider:
    """Provide a key from a file (hex-encoded content)."""

    def __init__(self, path: str):
        self._path = path

    def get_symmetric_key(self) -> bytes:
        with open(self._path, "r") as f:
            hex_key = f.read().strip()
        raw = bytes.fromhex(hex_key)
        if len(raw) != 32:
            raise ValueError("Key must be exactly 32 bytes (64 hex characters).")
        return raw

