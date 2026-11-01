"""Run the API with uvicorn: python -m sentinelops.api"""

import uvicorn


def main() -> None:
    # Forwarded headers are interpreted only by identity.dependencies.client_ip (trusted proxies).
    uvicorn.run(
        "sentinelops.api.app:create_app",
        factory=True,
        host="0.0.0.0",  # noqa: S104  # container-internal bind
        port=8000,
        proxy_headers=False,
        server_header=False,
    )


if __name__ == "__main__":
    main()
