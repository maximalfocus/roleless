from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from roleless.database import Database
from tests.conftest import auth


@pytest.mark.parametrize("token", ["demo-agent-token", "demo-contractor-token"])
def test_denylist_allows_agent_and_later_contractor_to_close_every_open_ticket(
    vulnerable_client: TestClient, token: str
) -> None:
    response = vulnerable_client.post("/admin/tickets/bulk-close", headers=auth(token))
    assert response.status_code == 200
    assert response.json() == {"closed": 2}
    tickets = vulnerable_client.get("/tickets", headers=auth(token)).json()
    assert all(ticket["status"] == "closed" for ticket in tickets)


def test_denylist_refuses_only_viewer_and_preserves_state(
    vulnerable_client: TestClient,
) -> None:
    database: Database = vulnerable_client.app.state.database
    before = database.snapshot()
    response = vulnerable_client.post(
        "/admin/tickets/bulk-close", headers=auth("demo-viewer-token")
    )
    assert response.status_code == 403
    assert response.json() == {"detail": "Forbidden"}
    assert database.snapshot() == before


def test_client_asserted_admin_role_returns_contact_to_agent(
    vulnerable_client: TestClient,
) -> None:
    identity = vulnerable_client.get("/me", headers=auth("demo-agent-token"))
    response = vulnerable_client.post(
        "/admin/customers/customer-1/contact",
        headers={**auth("demo-agent-token"), "X-Actor-Role": "admin"},
    )
    assert identity.json()["role"] == "agent"
    assert response.status_code == 200
    assert response.json()["email"] == "hello@example.invalid"


def test_vulnerable_app_trusts_role_header_in_both_directions(
    vulnerable_client: TestClient,
) -> None:
    response = vulnerable_client.post(
        "/admin/customers/customer-1/contact",
        headers={**auth("demo-admin-token"), "X-Actor-Role": "viewer"},
    )
    assert response.status_code == 403


def test_secure_checked_wrong_contrasts_share_uniform_refusal_and_preserve_state(
    client: TestClient,
) -> None:
    database: Database = client.app.state.database
    before = database.snapshot()
    responses = [
        client.post(
            "/admin/users/agent-1/role",
            headers=auth("demo-agent-token"),
            json={"role": "admin"},
        ),
        client.post("/admin/export", headers=auth("demo-agent-token")),
        client.post("/admin/tickets/bulk-close", headers=auth("demo-agent-token")),
        client.post(
            "/admin/customers/customer-1/contact",
            headers={**auth("demo-agent-token"), "X-Actor-Role": "admin"},
        ),
    ]
    assert [response.status_code for response in responses] == [403, 403, 403, 403]
    assert {response.text for response in responses} == {'{"detail":"Forbidden"}'}
    assert database.snapshot() == before


def test_secure_app_ignores_role_header_in_both_directions(client: TestClient) -> None:
    agent = client.post(
        "/admin/customers/customer-1/contact",
        headers={**auth("demo-agent-token"), "X-Actor-Role": "admin"},
    )
    admin = client.post(
        "/admin/customers/customer-1/contact",
        headers={**auth("demo-admin-token"), "X-Actor-Role": "viewer"},
    )
    assert agent.status_code == 403
    assert admin.status_code == 200


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("POST", "/tickets", {"subject": "No", "assignee_id": "agent-1"}),
        ("POST", "/tickets/1/comments", {"body": "No"}),
        ("POST", "/tickets/1/reassign", {"assignee_id": "agent-2"}),
        ("POST", "/admin/tickets/bulk-close", None),
        ("POST", "/admin/users/viewer-1/role", {"role": "agent"}),
        ("GET", "/admin/export", None),
        ("POST", "/admin/export", None),
        ("POST", "/admin/customers/customer-1/contact", None),
    ],
)
def test_secure_contractor_has_no_capability_beyond_reading_tickets(
    client: TestClient, method: str, path: str, body: dict[str, Any] | None
) -> None:
    response = client.request(method, path, headers=auth("demo-contractor-token"), json=body)
    assert response.status_code == 403
    assert response.json() == {"detail": "Forbidden"}
