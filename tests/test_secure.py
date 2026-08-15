from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from roleless.database import Database
from roleless.policy import ROLE_PERMISSIONS, ROUTE_PERMISSIONS
from roleless.secure import create_app, validate_policy_completeness
from tests.conftest import auth


def test_health_is_the_only_public_application_route(client: TestClient) -> None:
    assert client.get("/health").json() == {"status": "ok"}
    assert client.get("/tickets").status_code == 401


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": "Basic demonstration"},
        {"Authorization": "Bearer"},
        {"Authorization": "Bearer unknown-demo-token"},
    ],
)
def test_authentication_failures_are_generic(client: TestClient, headers: dict[str, str]) -> None:
    response = client.get("/me", headers=headers)
    assert response.status_code == 401
    assert response.json() == {"detail": "Unauthorized"}
    assert response.headers["www-authenticate"] == "Bearer"


@pytest.mark.parametrize(
    ("token", "role"),
    [
        ("demo-viewer-token", "viewer"),
        ("demo-agent-token", "agent"),
        ("demo-supervisor-token", "supervisor"),
        ("demo-admin-token", "admin"),
        ("demo-contractor-token", "contractor"),
    ],
)
def test_identity_comes_from_stored_user(client: TestClient, token: str, role: str) -> None:
    response = client.get("/me", headers={**auth(token), "X-Actor-Role": "admin"})
    assert response.status_code == 200
    assert response.json()["role"] == role


def test_legitimate_role_lifecycle(client: TestClient) -> None:
    assert client.get("/tickets", headers=auth("demo-viewer-token")).status_code == 200
    assert client.get("/tickets", headers=auth("demo-contractor-token")).status_code == 200

    created = client.post(
        "/tickets",
        headers=auth("demo-agent-token"),
        json={"subject": "Fresh fictional request", "assignee_id": "agent-1"},
    )
    assert created.status_code == 201
    ticket_id = created.json()["id"]
    commented = client.post(
        f"/tickets/{ticket_id}/comments",
        headers=auth("demo-agent-token"),
        json={"body": "Demonstration comment"},
    )
    assert commented.status_code == 201
    assert commented.json()["ticket_id"] == ticket_id

    reassigned = client.post(
        f"/tickets/{ticket_id}/reassign",
        headers=auth("demo-supervisor-token"),
        json={"assignee_id": "agent-2"},
    )
    assert reassigned.status_code == 200
    assert reassigned.json()["assignee_id"] == "agent-2"

    granted = client.post(
        "/admin/users/viewer-1/role",
        headers=auth("demo-admin-token"),
        json={"role": "agent"},
    )
    assert granted.status_code == 200
    assert granted.json()["role"] == "agent"

    closed = client.post("/admin/tickets/bulk-close", headers=auth("demo-admin-token"))
    assert closed.status_code == 200
    assert closed.json()["closed"] >= 1
    assert all(
        ticket["status"] == "closed"
        for ticket in client.get("/tickets", headers=auth("demo-admin-token")).json()
    )

    exported = client.post("/admin/export", headers=auth("demo-admin-token"))
    assert [customer["id"] for customer in exported.json()] == ["customer-1", "customer-2"]
    contact = client.post("/admin/customers/customer-1/contact", headers=auth("demo-admin-token"))
    assert contact.status_code == 200
    assert contact.json()["email"].endswith(".invalid")


@pytest.mark.parametrize(
    ("method", "path", "token", "body"),
    [
        ("POST", "/tickets", "demo-viewer-token", {"subject": "No", "assignee_id": "agent-1"}),
        ("POST", "/tickets/1/reassign", "demo-agent-token", {"assignee_id": "agent-2"}),
        ("POST", "/admin/tickets/bulk-close", "demo-supervisor-token", None),
        ("POST", "/admin/users/viewer-1/role", "demo-contractor-token", {"role": "agent"}),
        ("GET", "/admin/export", "demo-agent-token", None),
        ("POST", "/admin/export", "demo-agent-token", None),
        ("POST", "/admin/customers/customer-1/contact", "demo-agent-token", None),
    ],
)
def test_function_refusals_are_uniform_and_leave_state_unchanged(
    client: TestClient, method: str, path: str, token: str, body: dict[str, str] | None
) -> None:
    database: Database = client.app.state.database
    before = database.snapshot()
    response = client.request(method, path, headers=auth(token), json=body)
    assert response.status_code == 403
    assert response.json() == {"detail": "Forbidden"}
    assert database.snapshot() == before


def test_each_function_refusal_emits_one_safe_audit_event(
    client: TestClient, capsys: pytest.CaptureFixture[str]
) -> None:
    token = "demo-agent-token"
    response = client.post(
        "/admin/customers/customer-1/contact",
        headers={**auth(token), "X-Actor-Role": "admin", "X-Request-ID": "request-demo-1"},
    )
    assert response.status_code == 403
    lines = [line for line in capsys.readouterr().out.splitlines() if line]
    assert len(lines) == 1
    event = json.loads(lines[0])
    assert event == {
        "actor_id": "agent-1",
        "actor_role": "agent",
        "event": "function_authorization",
        "function": "POST /admin/customers/{customer_id}/contact",
        "outcome": "refused",
        "request_id": "request-demo-1",
        "required_permission": "customers:contact:read",
    }
    serialized = lines[0]
    for forbidden_value in (token, "Authorization", "X-Actor-Role", "hello@example.invalid"):
        assert forbidden_value not in serialized


def test_client_asserted_role_is_inert_in_both_directions(client: TestClient) -> None:
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


def test_admin_cannot_change_self_but_can_change_another_user(client: TestClient) -> None:
    before = client.get("/me", headers=auth("demo-admin-token")).json()
    self_change = client.post(
        "/admin/users/admin-1/role",
        headers=auth("demo-admin-token"),
        json={"role": "viewer"},
    )
    other_change = client.post(
        "/admin/users/viewer-1/role",
        headers=auth("demo-admin-token"),
        json={"role": "agent"},
    )
    assert self_change.status_code == 403
    assert self_change.json() == {"detail": "Forbidden"}
    assert client.get("/me", headers=auth("demo-admin-token")).json() == before
    assert other_change.status_code == 200


def test_agent_can_comment_only_on_assigned_ticket(client: TestClient) -> None:
    own = client.post(
        "/tickets/1/comments",
        headers=auth("demo-agent-token"),
        json={"body": "Allowed"},
    )
    other = client.post(
        "/tickets/2/comments",
        headers=auth("demo-agent-token"),
        json={"body": "Refused"},
    )
    assert own.status_code == 201
    assert other.status_code == 403
    assert other.json() == {"detail": "Forbidden"}


def test_policy_is_complete_and_allowlisted(tmp_path: Path) -> None:
    app = create_app(str(tmp_path / "complete.db"))
    validate_policy_completeness(app)
    expected_permissions = {
        "viewer": frozenset({"identity:read", "tickets:read"}),
        "contractor": frozenset({"identity:read", "tickets:read"}),
        "agent": frozenset({"identity:read", "tickets:read", "tickets:create", "tickets:comment"}),
        "supervisor": frozenset(
            {
                "identity:read",
                "tickets:read",
                "tickets:create",
                "tickets:comment",
                "tickets:reassign",
            }
        ),
        "admin": frozenset(
            {
                "identity:read",
                "tickets:read",
                "tickets:create",
                "tickets:comment",
                "tickets:reassign",
                "tickets:bulk-close",
                "users:grant-role",
                "customers:export",
                "customers:contact:read",
            }
        ),
    }
    assert expected_permissions == ROLE_PERMISSIONS


def test_startup_fails_for_route_without_policy(tmp_path: Path) -> None:
    app = create_app(str(tmp_path / "incomplete.db"))

    @app.get("/undeclared")
    def undeclared() -> dict[str, bool]:
        return {"unsafe": True}

    with pytest.raises(RuntimeError, match="missing=.*undeclared"), TestClient(app):
        pass


def test_runtime_fails_closed_when_declaration_disappears(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = ("POST", "/admin/export")
    monkeypatch.delitem(ROUTE_PERMISSIONS, key)
    response = client.post("/admin/export", headers=auth("demo-admin-token"))
    assert response.status_code == 403
    assert response.json() == {"detail": "Forbidden"}


def test_database_transaction_rolls_back_every_change(tmp_path: Path) -> None:
    database = Database(str(tmp_path / "rollback.db"))
    database.initialize()
    before = database.snapshot()
    with (
        pytest.raises(RuntimeError, match="simulated failure"),
        database.transaction() as connection,
    ):
        connection.execute("UPDATE tickets SET status = 'closed'")
        connection.execute("UPDATE users SET role = 'admin' WHERE id = 'agent-1'")
        raise RuntimeError("simulated failure")
    assert database.snapshot() == before


def test_fixtures_are_recreated_deterministically(tmp_path: Path) -> None:
    database = Database(str(tmp_path / "fresh.db"))
    database.initialize()
    original = database.snapshot()
    database.bulk_close()
    database.grant_role("viewer-1", "agent")
    database.initialize()
    assert database.snapshot() == original


def test_all_policy_routes_are_registered() -> None:
    app: FastAPI = create_app("/tmp/not-started-roleless.db")
    validate_policy_completeness(app)
    assert len(ROUTE_PERMISSIONS) == 10
