"""
CipherSweet backends: NaCl (ModernCrypto) and FIPS (FIPSCrypto).

NaCl backend:
  Format: "nacl:" + base64url(nonce[24] + xchacha20poly1305_ciphertext)
  Algorithm: XChaCha20-Poly1305 (via PyNaCl / libsodium)

FIPS backend:
  Format: "fips:" + base64url(hkdf_salt[32] + aes_nonce[16] + hmac_tag[48] + ciphertext)
  Algorithm: AES-256-CTR + HMAC-SHA384 (encrypt-then-MAC, HKDF key splitting)
"""

import base64
import hmac as hmac_mod
import hashlib

from .util import hkdf_sha384, ciphersweet_pack


def _base64url_decode(s: str) -> bytes:
    """Decode base64url with padding."""
    s = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


class NaClBackend:
    """
    ModernCrypto backend: XChaCha20-Poly1305.
    Header: "nacl:"
    Nonce size: 24 bytes
    """

    HEADER = b"nacl:"
    NONCE_SIZE = 24

    def decrypt(self, ciphertext: str, key: bytes) -> str:
        """
        Decrypt a NaCl-backend ciphertext string.

        Args:
            ciphertext: The full ciphertext string from the database (e.g. "nacl:...")
            key: 32-byte field encryption key

        Returns:
            Decrypted plaintext string.
        """
        if isinstance(ciphertext, str):
            ciphertext_bytes = ciphertext.encode("utf-8")
        else:
            ciphertext_bytes = ciphertext

        if ciphertext_bytes[:5] != self.HEADER:
            raise ValueError(
                f"Invalid ciphertext: expected header 'nacl:', got '{ciphertext_bytes[:5]}'"
            )

        payload = _base64url_decode(ciphertext_bytes[5:].decode("utf-8"))

        min_len = self.NONCE_SIZE + 16  # nonce + poly1305 tag
        if len(payload) < min_len:
            raise ValueError(
                f"Ciphertext payload too short: {len(payload)} < {min_len}"
            )

        nonce = payload[: self.NONCE_SIZE]
        encrypted = payload[self.NONCE_SIZE :]

        try:
            import nacl.secret
            import nacl.bindings
        except ImportError:
            raise ImportError(
                "PyNaCl is required for NaCl backend. Install with: pip install pynacl"
            )

        # Match CipherSweet ModernCrypto and ciphersweet-go: AAD = nonce || caller_aad.
        # We currently support caller_aad="" at this layer, so this is equivalent
        # to using just nonce as associated data.
        plaintext = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
            ciphertext=encrypted,
            aad=nonce,
            nonce=nonce,
            key=key,
        )
        return plaintext.decode("utf-8")


class FIPSBackend:
    """
    FIPSCrypto backend: AES-256-CTR + HMAC-SHA384.
    Header: "fips:"
    Layout after base64url decode:
      [0:32]   HKDF salt
      [32:48]  AES-CTR nonce (16 bytes)
      [48:96]  HMAC-SHA384 tag (48 bytes)
      [96:]    AES-256-CTR ciphertext
    """

    HEADER = b"fips:"
    HKDF_SALT_SIZE = 32
    AES_NONCE_SIZE = 16
    HMAC_TAG_SIZE = 48  # SHA-384 output = 48 bytes

    def decrypt(self, ciphertext: str, key: bytes) -> str:
        """
        Decrypt a FIPS-backend ciphertext string.

        Args:
            ciphertext: The full ciphertext string from the database (e.g. "fips:...")
            key: 32-byte field encryption key

        Returns:
            Decrypted plaintext string.
        """
        if isinstance(ciphertext, str):
            ciphertext_bytes = ciphertext.encode("utf-8")
        else:
            ciphertext_bytes = ciphertext

        if ciphertext_bytes[:5] != self.HEADER:
            raise ValueError(
                f"Invalid ciphertext: expected header 'fips:', got '{ciphertext_bytes[:5]}'"
            )

        payload = _base64url_decode(ciphertext_bytes[5:].decode("utf-8"))

        min_len = self.HKDF_SALT_SIZE + self.AES_NONCE_SIZE + self.HMAC_TAG_SIZE
        if len(payload) < min_len:
            raise ValueError(
                f"Ciphertext payload too short: {len(payload)} < {min_len}"
            )

        hkdf_salt = payload[: self.HKDF_SALT_SIZE]
        aes_nonce = payload[self.HKDF_SALT_SIZE : self.HKDF_SALT_SIZE + self.AES_NONCE_SIZE]
        hmac_tag = payload[
            self.HKDF_SALT_SIZE + self.AES_NONCE_SIZE :
            self.HKDF_SALT_SIZE + self.AES_NONCE_SIZE + self.HMAC_TAG_SIZE
        ]
        encrypted = payload[self.HKDF_SALT_SIZE + self.AES_NONCE_SIZE + self.HMAC_TAG_SIZE :]

        # Derive subkeys using HKDF-SHA384
        enc_key = hkdf_sha384(key, 32, info=b"AES-256-CTR", salt=hkdf_salt)
        mac_key = hkdf_sha384(key, 48, info=b"HMAC-SHA-384", salt=hkdf_salt)

        # Verify MAC: HMAC-SHA384(mac_key, pack([header, hkdf_salt, aes_nonce, ciphertext]))
        mac_msg = ciphersweet_pack([self.HEADER, hkdf_salt, aes_nonce, encrypted])
        expected_tag = hmac_mod.new(mac_key, mac_msg, hashlib.sha384).digest()

        if not hmac_mod.compare_digest(expected_tag, hmac_tag):
            raise ValueError("MAC verification failed: ciphertext may be tampered.")

        # Decrypt AES-256-CTR
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend

        cipher = Cipher(
            algorithms.AES(enc_key),
            modes.CTR(aes_nonce),
            backend=default_backend(),
        )
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(encrypted) + decryptor.finalize()
        return plaintext.decode("utf-8")

