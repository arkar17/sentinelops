"""Test configuration. Tests never need a running database or network access."""

from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr

from sentinelops.api.app import create_app
from sentinelops.config import Environment, Settings

# Port 1 on loopback: nothing listens there, so any accidental connection fails fast.
UNREACHABLE_DB_URL = "postgresql+asyncpg://sentinelops@127.0.0.1:1/sentinelops_test"


@pytest.fixture
def settings() -> Settings:
    return Settings(
        env=Environment.TEST,
        database_url=SecretStr(UNREACHABLE_DB_URL),
        readiness_timeout_seconds=1.0,
    )


@pytest.fixture
def app(settings: Settings) -> FastAPI:
    return create_app(settings)


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client
