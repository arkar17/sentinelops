from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel

from sentinelops.errors import AppError


class Payload(BaseModel):
    count: int


def _add_routes(app: FastAPI) -> None:
    @app.get("/_test/app-error")
    async def app_error() -> None:
        raise AppError(409, "CONFLICT_EXAMPLE", "Example conflict")

    @app.get("/_test/boom")
    async def boom() -> None:
        raise RuntimeError("secret-internal-detail")

    @app.post("/_test/validate")
    async def validate(payload: Payload) -> Payload:
        return payload


def test_unknown_route_uses_error_envelope(client: TestClient) -> None:
    response = client.get("/does-not-exist")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "NOT_FOUND"


def test_app_error_maps_status_and_code(app: FastAPI, client: TestClient) -> None:
    _add_routes(app)
    response = client.get("/_test/app-error")
    assert response.status_code == 409
    assert response.json()["error"] == {
        "code": "CONFLICT_EXAMPLE",
        "message": "Example conflict",
        "request_id": response.headers["X-Request-ID"],
    }


def test_unhandled_error_hides_internal_details(app: FastAPI, client: TestClient) -> None:
    _add_routes(app)
    response = client.get("/_test/boom")
    assert response.status_code == 500
    assert response.json()["error"]["code"] == "INTERNAL_ERROR"
    assert "secret-internal-detail" not in response.text
    assert response.headers["X-Request-ID"]


def test_validation_error_does_not_echo_input(app: FastAPI, client: TestClient) -> None:
    _add_routes(app)
    response = client.post("/_test/validate", json={"count": "token-abc123"})
    assert response.status_code == 422
    body = response.json()["error"]
    assert body["code"] == "VALIDATION_ERROR"
    assert body["details"][0]["loc"] == ["body", "count"]
    assert "token-abc123" not in response.text


def test_wellformed_inbound_request_id_is_propagated(client: TestClient) -> None:
    response = client.get("/healthz", headers={"X-Request-ID": "abc12345-trace"})
    assert response.headers["X-Request-ID"] == "abc12345-trace"


def test_malformed_inbound_request_id_is_replaced(client: TestClient) -> None:
    response = client.get("/healthz", headers={"X-Request-ID": "bad id\r\ninjected"})
    assert response.headers["X-Request-ID"] != "bad id\r\ninjected"
    assert len(response.headers["X-Request-ID"]) == 32
