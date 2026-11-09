"""Encrypted JSON documents (``JsonFieldMap`` and ``EncryptedJsonField``)."""

from __future__ import annotations

import json
import struct
from typing import Any, Dict, Iterable, List, Optional, Sequence, Union

from . import constants as C
from ._types import convert_from_bytes, convert_to_bytes
from ._util import crc32c_hex, hash_equals, hkdf, php_json_encode
from .aad import AAD, AADLike
from .backend import Backend
from .engine import CipherSweet
from .exceptions import CipherSweetException, InvalidCiphertextException, JsonMapException
from .key import SymmetricKey

PathElement = Union[str, int]
Indices = Union[PathElement, Sequence[PathElement]]


def _as_path(indices: Indices) -> List[PathElement]:
    if isinstance(indices, bool):
        raise JsonMapException("Invalid type")
    if isinstance(indices, (str, int)):
        return [indices]
    return list(indices)


class JsonFieldMap:
    """Describes which paths inside a JSON document are encrypted, and as what type."""

    def __init__(self) -> None:
        self.fields: Dict[str, str] = {}

    @classmethod
    def from_string(cls, string: str) -> JsonFieldMap:
        crc, payload = string[:8], string[8:]
        if not hash_equals(crc32c_hex(payload.encode("utf-8")).encode(), crc.encode()):
            raise CipherSweetException("CRC32C invalid; was config corrupted?")
        try:
            decoded = json.loads(payload)
        except ValueError as exc:
            raise CipherSweetException("Invalid JSON encoding") from exc
        if not isinstance(decoded, dict):
            raise CipherSweetException("Invalid JSON encoding")
        if "fields" not in decoded:
            raise CipherSweetException("Invalid JSON: no fields key")
        self = cls()
        for flat, type_ in decoded["fields"].items():
            if not isinstance(flat, str) or not isinstance(type_, str):
                raise CipherSweetException("Invalid field")
            self._unflatten(flat)
        self.fields = dict(decoded["fields"])
        return self

    def add_boolean_field(self, indices: Indices) -> JsonFieldMap:
        return self.add_field(_as_path(indices), C.TYPE_BOOLEAN)

    def add_float_field(self, indices: Indices) -> JsonFieldMap:
        return self.add_field(_as_path(indices), C.TYPE_FLOAT)

    def add_integer_field(self, indices: Indices) -> JsonFieldMap:
        return self.add_field(_as_path(indices), C.TYPE_INT)

    def add_text_field(self, indices: Indices) -> JsonFieldMap:
        return self.add_field(_as_path(indices), C.TYPE_TEXT)

    def add_field(self, indices: Sequence[PathElement], type_: str) -> JsonFieldMap:
        self.fields[self._flatten(indices)] = type_
        return self

    def add_map_field_from_template(self, root: Indices, template: JsonFieldMap) -> JsonFieldMap:
        root_path = _as_path(root)
        for mapping in template.get_mapping():
            self.add_field(root_path + list(mapping["path"]), mapping["type"])
        return self

    @staticmethod
    def _flatten(indices: Iterable[PathElement]) -> str:
        pieces = []
        for index in indices:
            if isinstance(index, bool):
                raise JsonMapException("Invalid type")
            if isinstance(index, int):
                pieces.append("#" + struct.pack(">q", index).hex())
            elif isinstance(index, str):
                pieces.append("$" + index.encode("utf-8").hex())
            else:
                raise JsonMapException("Invalid type")
        return ".".join(pieces)

    @staticmethod
    def _unflatten(flat: str) -> List[PathElement]:
        path: List[PathElement] = []
        for piece in flat.split("."):
            if not piece:
                raise CipherSweetException("Unknown path type: ")
            try:
                decoded = bytes.fromhex(piece[1:])
            except ValueError as exc:
                raise CipherSweetException("Invalid hex encoding") from exc
            if piece[0] == "#":
                if len(decoded) != 8:
                    raise CipherSweetException("Invalid integer encoding")
                path.append(struct.unpack(">q", decoded)[0])
            elif piece[0] == "$":
                path.append(decoded.decode("utf-8"))
            else:
                raise CipherSweetException(f"Unknown path type: {piece[0]}")
        return path

    def get_mapping(self) -> List[Dict[str, Any]]:
        return [
            {"flat": flat, "path": self._unflatten(flat), "type": type_}
            for flat, type_ in self.fields.items()
        ]

    def to_string(self) -> str:
        payload = php_json_encode({"fields": self.fields})
        return crc32c_hex(payload.encode("utf-8")) + payload

    __str__ = to_string


class EncryptedJsonField:
    """Encrypts selected values inside a JSON document, each under its own sub-key."""

    def __init__(
        self,
        backend: Backend,
        root_key: SymmetricKey,
        field_map: JsonFieldMap,
        strict: bool = True,
    ) -> None:
        self.backend = backend
        self.root_key = root_key
        self.field_map = field_map
        self.strict = strict

    @classmethod
    def create(
        cls,
        engine: CipherSweet,
        field_map: JsonFieldMap,
        table_name: str,
        field_name: str,
        strict: bool = True,
    ) -> EncryptedJsonField:
        return cls(
            engine.get_backend(),
            engine.get_field_symmetric_key(table_name, field_name),
            field_map,
            strict,
        )

    def add_boolean_field(self, indices: Indices) -> EncryptedJsonField:
        self.field_map.add_boolean_field(indices)
        return self

    def add_float_field(self, indices: Indices) -> EncryptedJsonField:
        self.field_map.add_float_field(indices)
        return self

    def add_integer_field(self, indices: Indices) -> EncryptedJsonField:
        self.field_map.add_integer_field(indices)
        return self

    def add_text_field(self, indices: Indices) -> EncryptedJsonField:
        self.field_map.add_text_field(indices)
        return self

    def add_field(self, indices: Sequence[PathElement], type_: str) -> EncryptedJsonField:
        self.field_map.add_field(indices, type_)
        return self

    def set_strict_mode(self, strict: bool = False) -> EncryptedJsonField:
        self.strict = strict
        return self

    def derive_key(self, flat_path: str) -> SymmetricKey:
        return SymmetricKey(hkdf(self.root_key.get_raw_key(), None, C.DS_JSON + flat_path.encode("utf-8")))

    def decrypt_json(self, encoded: Union[str, bytes], aad: AADLike = "") -> Any:
        try:
            document = json.loads(encoded)
        except ValueError as exc:
            raise CipherSweetException("Could not decode JSON") from exc
        if not isinstance(document, (dict, list)):
            raise CipherSweetException("Could not decode JSON")
        for mapped in self.field_map.get_mapping():
            if not mapped["path"]:
                continue
            key = self.derive_key(mapped["flat"])
            self._walk(document, mapped["path"], mapped["type"], key, aad, decrypting=True)
        return document

    def encrypt_json(self, document: Any, aad: AADLike = "") -> str:
        document = json.loads(json.dumps(document))  # deep copy, JSON types only
        for mapped in self.field_map.get_mapping():
            if not mapped["path"]:
                continue
            key = self.derive_key(mapped["flat"])
            self._walk(document, mapped["path"], mapped["type"], key, aad, decrypting=False)
        return php_json_encode(document)

    def _walk(
        self, doc: Any, path: List[PathElement], type_: str, key: SymmetricKey, aad: AADLike, decrypting: bool
    ) -> None:
        parent: Any = None
        last: Any = None
        curr = doc
        for depth, step in enumerate(path):
            container_key = self._resolve(curr, step)
            if container_key is None:
                if self.strict:
                    pre = "de" if decrypting else "en"
                    raise CipherSweetException(
                        f"Required JSON field {step} was missing at depth {depth} on {pre}cryptJSON() in strict mode"
                    )
                return
            parent, last = curr, container_key
            curr = curr[container_key]
        if curr is None:
            return
        canon = AAD.literal(aad).canonicalize()
        if decrypting:
            if not isinstance(curr, str):
                raise InvalidCiphertextException("Decryption failed")
            parent[last] = convert_from_bytes(self.backend.decrypt(curr, key, canon), type_)
        else:
            parent[last] = self.backend.encrypt(convert_to_bytes(curr, type_), key, canon)

    @staticmethod
    def _resolve(container: Any, step: PathElement) -> Optional[Any]:
        """Find ``step`` in a JSON container, using PHP array key semantics
        (``0`` and ``"0"`` are the same key)."""
        if isinstance(container, list):
            try:
                idx = int(step)
            except (TypeError, ValueError):
                return None
            if str(idx) != str(step) or not 0 <= idx < len(container):
                return None
            return idx
        if isinstance(container, dict):
            if isinstance(step, int):
                return str(step) if str(step) in container else None
            return step if step in container else None
        return None
