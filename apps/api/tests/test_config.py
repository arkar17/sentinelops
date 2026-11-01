import base64
import os

import pytest
from pydantic import SecretStr, ValidationError

from sentinelops.api.app import create_app
from sentinelops.config import Environment, Settings


def test_database_url_is_required(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SENTINELOPS_DATABASE_URL", raising=False)
    with pytest.raises(ValidationError):
        Settings()  # pyright: ignore[reportCallIssue]


def test_database_url_must_use_asyncpg() -> None:
    with pytest.raises(ValidationError):
        Settings(database_url=SecretStr("postgresql://u@localhost/db"))


def test_database_url_is_not_revealed_by_repr() -> None:
    settings = Settings(database_url=SecretStr("postgresql+asyncpg://u:hunter2@localhost/db"))
    assert "hunter2" not in repr(settings)


def _key() -> str:
    return base64.b64encode(os.urandom(32)).decode()  # per test, never stored


def test_settings_load_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINELOPS_DATABASE_URL", "postgresql+asyncpg://u@localhost/db")
    monkeypatch.setenv("SENTINELOPS_ENV", "production")
    monkeypatch.setenv("SENTINELOPS_MFA_KEYS", f'{{"k1": "{_key()}"}}')
    monkeypatch.setenv("SENTINELOPS_MFA_ACTIVE_KEY_ID", "k1")
    settings = Settings()  # pyright: ignore[reportCallIssue]
    assert settings.env is Environment.PRODUCTION
    assert settings.require_admin_mfa is True


def test_production_refuses_to_start_without_mfa_keys() -> None:
    with pytest.raises(ValidationError, match="admin MFA is required"):
        Settings(env=Environment.PRODUCTION, database_url=SecretStr("postgresql+asyncpg://u@h/db"))


def test_mfa_policy_defaults_and_overrides() -> None:
    url = SecretStr("postgresql+asyncpg://u@h/db")
    assert Settings(database_url=url).require_admin_mfa is False  # development
    forced = Settings(
        database_url=url,
        admin_mfa_required=True,
        mfa_keys={"k": SecretStr(_key())},
        mfa_active_key_id="k",
    )
    assert forced.require_admin_mfa is True


@pytest.mark.parametrize("value", [["not-a-network"], ["10.0.0.0/33"]])
def test_trusted_proxies_must_be_networks(value: list[str]) -> None:
    with pytest.raises(ValidationError):
        Settings(database_url=SecretStr("postgresql+asyncpg://u@h/db"), trusted_proxies=value)


def test_api_docs_disabled_in_production() -> None:
    settings = Settings(
        env=Environment.PRODUCTION,
        database_url=SecretStr("postgresql+asyncpg://u@localhost/db"),
        mfa_keys={"k1": SecretStr(_key())},
        mfa_active_key_id="k1",
    )
    app = create_app(settings)
    assert app.docs_url is None
    assert app.openapi_url is None
