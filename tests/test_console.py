from __future__ import annotations

import re
import threading
import urllib.request
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from roleless.cors import CONSOLE_HEADERS, CONSOLE_METHODS, CONSOLE_ORIGIN
from tests.conftest import auth

ROOT = Path(__file__).parents[1]
CONSOLE = ROOT / "console"
API_BASES = {"http://127.0.0.1:8000", "http://127.0.0.1:8001"}


def test_console_static_surface_is_served() -> None:
    handler = partial(SimpleHTTPRequestHandler, directory=str(CONSOLE))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        with urllib.request.urlopen(f"{base}/", timeout=2) as response:
            assert response.status == 200
            assert b"Send it anyway" in response.read()
        for asset in ("app.js", "style.css"):
            with urllib.request.urlopen(f"{base}/{asset}", timeout=2) as response:
                assert response.status == 200
                assert response.read()
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_console_has_exact_api_allowlist_and_no_external_assets() -> None:
    sources = "\n".join(path.read_text() for path in sorted(CONSOLE.iterdir()))
    urls = set(re.findall(r"https?://[^\"'\s<]+", sources))
    assert urls == API_BASES

    script = (CONSOLE / "app.js").read_text()
    allowlist_match = re.search(
        r"const API_BASES = Object\.freeze\(\[(.*?)\]\);", script, re.DOTALL
    )
    assert allowlist_match is not None
    assert set(re.findall(r'"(http://[^\"]+)"', allowlist_match.group(1))) == API_BASES
    assert "API_BASES.includes(base)" in script

    html = (CONSOLE / "index.html").read_text()
    assert not re.search(r"<(?:script|link)[^>]+(?:src|href)=[\"']https?://", html)
    assert 'type="text"' not in html
    assert "<textarea" not in html


def test_console_uses_only_fictional_tokens_and_has_no_persistent_client_features() -> None:
    sources = "\n".join(path.read_text() for path in sorted(CONSOLE.iterdir()))
    assert set(re.findall(r"demo-[a-z]+-token", sources)) == {
        "demo-viewer-token",
        "demo-agent-token",
        "demo-supervisor-token",
        "demo-admin-token",
        "demo-contractor-token",
    }
    for excluded in (
        "serviceWorker",
        "localStorage",
        "sessionStorage",
        "indexedDB",
        "WebSocket",
        "EventSource",
    ):
        assert excluded not in sources


def test_console_declares_all_five_fixed_demonstration_requests() -> None:
    script = (CONSOLE / "app.js").read_text()
    for action, path in {
        "grant-current": "/admin/users/${actor.id}/role",
        "post-export": "/admin/export",
        "legacy-grant": "/api/v1/users/${actor.id}/role",
        "bulk-close": "/admin/tickets/bulk-close",
        "forged-contact": "/admin/customers/customer-1/contact",
    }.items():
        assert f'"{action}"' in script
        assert path in script
    assert '"X-Actor-Role": "admin"' in script
    assert "secure-response-output" in script
    assert "vulnerable-response-output" in script


@pytest.mark.parametrize("client_fixture", ["client", "vulnerable_client"])
def test_api_cors_allows_only_console_origin(
    request: pytest.FixtureRequest, client_fixture: str
) -> None:
    client: TestClient = request.getfixturevalue(client_fixture)
    allowed = client.get("/me", headers={**auth("demo-agent-token"), "Origin": CONSOLE_ORIGIN})
    assert allowed.status_code == 200
    assert allowed.headers["access-control-allow-origin"] == CONSOLE_ORIGIN
    assert "access-control-allow-credentials" not in allowed.headers

    denied = client.get(
        "/me", headers={**auth("demo-agent-token"), "Origin": "http://127.0.0.1:9999"}
    )
    assert denied.status_code == 200
    assert "access-control-allow-origin" not in denied.headers


@pytest.mark.parametrize("client_fixture", ["client", "vulnerable_client"])
def test_api_cors_preflight_is_narrow(request: pytest.FixtureRequest, client_fixture: str) -> None:
    client: TestClient = request.getfixturevalue(client_fixture)
    response = client.options(
        "/admin/customers/customer-1/contact",
        headers={
            "Origin": CONSOLE_ORIGIN,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "authorization,content-type,x-actor-role",
        },
    )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == CONSOLE_ORIGIN
    assert set(response.headers["access-control-allow-methods"].split(", ")) == set(CONSOLE_METHODS)
    allowed_headers = response.headers["access-control-allow-headers"].lower()
    assert all(header.lower() in allowed_headers for header in CONSOLE_HEADERS)

    denied = client.options(
        "/me",
        headers={
            "Origin": "https://example.invalid",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "authorization",
        },
    )
    assert denied.status_code == 400
    assert "access-control-allow-origin" not in denied.headers


CONSOLE_ACTIONS: list[tuple[str, str, dict[str, str], dict[str, Any] | None, int]] = [
    ("POST", "/admin/users/agent-1/role", {}, {"role": "admin"}, 403),
    ("POST", "/admin/export", {}, None, 403),
    ("POST", "/api/v1/users/agent-1/role", {}, {"role": "admin"}, 404),
    ("POST", "/admin/tickets/bulk-close", {}, None, 403),
    ("POST", "/admin/customers/customer-1/contact", {"X-Actor-Role": "admin"}, None, 403),
]


@pytest.mark.parametrize(("method", "path", "headers", "body", "secure_status"), CONSOLE_ACTIONS)
def test_console_actions_show_secure_refusal_or_deletion(
    client: TestClient,
    method: str,
    path: str,
    headers: dict[str, str],
    body: dict[str, Any] | None,
    secure_status: int,
) -> None:
    response = client.request(
        method,
        path,
        headers={**auth("demo-agent-token"), **headers, "Origin": CONSOLE_ORIGIN},
        json=body,
    )
    assert response.status_code == secure_status
    assert response.headers["access-control-allow-origin"] == CONSOLE_ORIGIN
    if secure_status == 403:
        assert response.json() == {"detail": "Forbidden"}


@pytest.mark.parametrize(("method", "path", "headers", "body", "_"), CONSOLE_ACTIONS)
def test_console_actions_show_vulnerable_impact(
    vulnerable_client: TestClient,
    method: str,
    path: str,
    headers: dict[str, str],
    body: dict[str, Any] | None,
    _: int,
) -> None:
    response = vulnerable_client.request(
        method,
        path,
        headers={**auth("demo-agent-token"), **headers, "Origin": CONSOLE_ORIGIN},
        json=body,
    )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == CONSOLE_ORIGIN


def test_compose_declares_hardened_default_console() -> None:
    compose = (ROOT / "compose.yaml").read_text()
    console_service = compose.split("  console:\n", 1)[1].split("\n  vulnerable:\n", 1)[0]
    assert "target: console" in console_service
    assert '"127.0.0.1:8080:8080"' in console_service
    assert "profiles:" not in console_service
    assert "read_only: true" in console_service
    assert "- ALL" in console_service
    assert "no-new-privileges:true" in console_service
    assert "networks: [published]" in console_service
