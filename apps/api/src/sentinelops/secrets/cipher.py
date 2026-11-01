"""AES-256-GCM encryption for organization secrets (ADR-015, NFR-011).

Associated data binds each ciphertext to organization, table, row and field, so a value copied
to another organization or row fails to decrypt. Stored form: base64(nonce || ciphertext+tag).
Plaintext never leaves this module except to its two consumers: catalog (write) and the probe
worker (read). The platform plane cannot import this package (import-linter).
"""

import base64
import binascii
import os
import uuid
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from sentinelops.config import Settings
from sentinelops.errors import AppError

_NONCE_BYTES = 12


class SecretsUnavailableError(AppError):
    def __init__(self) -> None:
        super().__init__(503, "SECRETS_UNAVAILABLE", "Secret storage is not configured")


class SecretDecryptError(Exception):
    """Ciphertext does not match its key or binding. Message never includes the value."""


@dataclass(frozen=True)
class SecretBinding:
    organization_id: uuid.UUID
    table: str
    row_id: uuid.UUID
    field: str

    def aad(self) -> bytes:
        return f"{self.organization_id}|{self.table}|{self.row_id}|{self.field}".encode()


@dataclass(frozen=True)
class Sealed:
    key_id: str
    ciphertext: str


class SecretBox:
    def __init__(self, keys: dict[str, bytes], active_key_id: str | None) -> None:
        self._keys = keys
        self._active = active_key_id

    @classmethod
    def from_settings(cls, settings: Settings) -> SecretBox:
        keys: dict[str, bytes] = {}
        for key_id, encoded in settings.secret_keys.items():
            try:
                raw = base64.b64decode(encoded.get_secret_value(), validate=True)
            except binascii.Error as exc:
                raise ValueError(f"Secret key {key_id!r} is not valid base64") from exc
            if len(raw) != 32:
                raise ValueError(f"Secret key {key_id!r} must be 32 bytes")
            keys[key_id] = raw
        if settings.secret_active_key_id is not None and settings.secret_active_key_id not in keys:
            raise ValueError("secret_active_key_id does not name a configured key")
        return cls(keys, settings.secret_active_key_id)

    def seal(self, plaintext: str, binding: SecretBinding) -> Sealed:
        if self._active is None:
            raise SecretsUnavailableError
        nonce = os.urandom(_NONCE_BYTES)
        sealed = AESGCM(self._keys[self._active]).encrypt(nonce, plaintext.encode(), binding.aad())
        return Sealed(self._active, base64.b64encode(nonce + sealed).decode())

    def open(self, key_id: str, ciphertext: str, binding: SecretBinding) -> str:
        key = self._keys.get(key_id)
        if key is None:
            raise SecretDecryptError("unknown key id")
        try:
            raw = base64.b64decode(ciphertext, validate=True)
            plain = AESGCM(key).decrypt(raw[:_NONCE_BYTES], raw[_NONCE_BYTES:], binding.aad())
        except (binascii.Error, InvalidTag, ValueError) as exc:
            raise SecretDecryptError("ciphertext does not match its binding") from exc
        return plain.decode()
