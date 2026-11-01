"""AES-GCM secret box (ADR-015)."""

import base64
import os
import uuid

import pytest
from pydantic import SecretStr

from sentinelops.config import Environment, Settings
from sentinelops.secrets.cipher import (
    SecretBinding,
    SecretBox,
    SecretDecryptError,
    SecretsUnavailableError,
)

ORG_A, ORG_B, ROW = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()


def box(*key_ids: str, active: str | None = "k1") -> SecretBox:
    keys = {k: SecretStr(base64.b64encode(os.urandom(32)).decode()) for k in key_ids}
    return SecretBox.from_settings(
        Settings(
            env=Environment.TEST,
            database_url=SecretStr("postgresql+asyncpg://u@localhost/db"),
            secret_keys=keys,
            secret_active_key_id=active,
        )
    )


def test_round_trip_and_ciphertext_is_opaque() -> None:
    secret_box = box("k1")
    binding = SecretBinding(ORG_A, "monitor", ROW, "url")
    sealed = secret_box.seal("https://api.example.com/?token=abc", binding)
    assert "token" not in sealed.ciphertext
    assert (
        secret_box.open(sealed.key_id, sealed.ciphertext, binding)
        == "https://api.example.com/?token=abc"
    )
    assert (
        sealed.ciphertext
        != secret_box.seal("https://api.example.com/?token=abc", binding).ciphertext
    )


@pytest.mark.parametrize(
    "other",
    [
        SecretBinding(ORG_B, "monitor", ROW, "url"),
        SecretBinding(ORG_A, "monitor", uuid.uuid4(), "url"),
        SecretBinding(ORG_A, "monitor", ROW, "headers"),
    ],
)
def test_ciphertext_cannot_move_between_orgs_rows_or_fields(other: SecretBinding) -> None:
    secret_box = box("k1")
    sealed = secret_box.seal("secret", SecretBinding(ORG_A, "monitor", ROW, "url"))
    with pytest.raises(SecretDecryptError):
        secret_box.open(sealed.key_id, sealed.ciphertext, other)


def test_tampering_and_unknown_keys_fail() -> None:
    secret_box = box("k1")
    binding = SecretBinding(ORG_A, "monitor", ROW, "url")
    sealed = secret_box.seal("secret", binding)
    tampered = base64.b64encode(
        bytes([base64.b64decode(sealed.ciphertext)[0] ^ 1])
        + base64.b64decode(sealed.ciphertext)[1:]
    ).decode()
    with pytest.raises(SecretDecryptError):
        secret_box.open(sealed.key_id, tampered, binding)
    with pytest.raises(SecretDecryptError):
        secret_box.open("k9", sealed.ciphertext, binding)


def test_key_rotation_keeps_old_ciphertexts_readable() -> None:
    keys = {k: SecretStr(base64.b64encode(os.urandom(32)).decode()) for k in ("old", "new")}
    base = {
        "env": Environment.TEST,
        "database_url": SecretStr("postgresql+asyncpg://u@localhost/db"),
        "secret_keys": keys,
    }
    old_box = SecretBox.from_settings(Settings(**base, secret_active_key_id="old"))  # type: ignore[arg-type]
    new_box = SecretBox.from_settings(Settings(**base, secret_active_key_id="new"))  # type: ignore[arg-type]
    binding = SecretBinding(ORG_A, "monitor", ROW, "url")
    sealed = old_box.seal("v", binding)
    assert new_box.open(sealed.key_id, sealed.ciphertext, binding) == "v"
    assert new_box.seal("v", binding).key_id == "new"


def test_missing_configuration() -> None:
    with pytest.raises(SecretsUnavailableError):
        box(active=None).seal("x", SecretBinding(ORG_A, "monitor", ROW, "url"))
    with pytest.raises(ValueError, match="32 bytes"):
        SecretBox.from_settings(
            Settings(
                env=Environment.TEST,
                database_url=SecretStr("postgresql+asyncpg://u@localhost/db"),
                secret_keys={"k1": SecretStr(base64.b64encode(b"short").decode())},
                secret_active_key_id="k1",
            )
        )


def test_dev_fixture_policy_refused_in_production() -> None:
    with pytest.raises(ValueError, match="dev-fixtures"):
        Settings(
            env=Environment.PRODUCTION,
            database_url=SecretStr("postgresql+asyncpg://u@localhost/db"),
            probe_policy="dev-fixtures",
        )
