from fastapi import FastAPI
from fastapi.testclient import TestClient

from sentinelops.api.health import DatabaseCheck, get_database_check


def test_healthz_is_ok_without_database(client: TestClient) -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_readyz_reports_ready_when_database_answers(app: FastAPI, client: TestClient) -> None:
    async def healthy() -> None:
        return None

    def override() -> DatabaseCheck:
        return healthy

    app.dependency_overrides[get_database_check] = override
    response = client.get("/readyz")
    assert response.status_code == 200
    assert response.json() == {"status": "ready", "checks": {"database": "ok"}}


def test_readyz_returns_structured_503_when_database_unreachable(client: TestClient) -> None:
    response = client.get("/readyz")
    assert response.status_code == 503
    error = response.json()["error"]
    assert error["code"] == "NOT_READY"
    assert "127.0.0.1" not in response.text  # no connection details leak
    assert error["request_id"] == response.headers["X-Request-ID"]


def test_readyz_times_out_slow_database(app: FastAPI, client: TestClient) -> None:
    import asyncio

    async def hangs() -> None:
        await asyncio.sleep(30)

    def override() -> DatabaseCheck:
        return hangs

    app.dependency_overrides[get_database_check] = override
    response = client.get("/readyz")
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "NOT_READY"
