from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from roleless.cli import render
from roleless.database import Database
from roleless.scenarios import run_comparison
from roleless.secure import create_app as create_secure_app
from roleless.vulnerable import create_app as create_vulnerable_app
from tests.conftest import auth


def test_vulnerable_app_requires_explicit_acknowledgement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ALLOW_VULNERABLE_DEMO", raising=False)
    app = create_vulnerable_app(str(tmp_path / "refused.db"))
    with pytest.raises(RuntimeError, match="ALLOW_VULNERABLE_DEMO=true"), TestClient(app):
        pass


def test_rung_one_agent_self_promotes_then_exports(vulnerable_client: TestClient) -> None:
    before = vulnerable_client.get("/me", headers=auth("demo-agent-token"))
    export_before = vulnerable_client.get("/admin/export", headers=auth("demo-agent-token"))
    grant = vulnerable_client.post(
        "/admin/users/agent-1/role",
        headers=auth("demo-agent-token"),
        json={"role": "admin"},
    )
    after = vulnerable_client.get("/me", headers=auth("demo-agent-token"))
    export_after = vulnerable_client.post("/admin/export", headers=auth("demo-agent-token"))
    assert before.json()["role"] == "agent"
    assert export_before.status_code == 403
    assert grant.status_code == 200
    assert after.json()["role"] == "admin"
    assert export_after.status_code == 200
    assert [customer["id"] for customer in export_after.json()] == [
        "customer-1",
        "customer-2",
    ]


def test_secure_app_refuses_rung_one_and_preserves_state(client: TestClient) -> None:
    database: Database = client.app.state.database
    before = database.snapshot()
    grant = client.post(
        "/admin/users/agent-1/role",
        headers=auth("demo-agent-token"),
        json={"role": "admin"},
    )
    exported = client.post("/admin/export", headers=auth("demo-agent-token"))
    assert grant.status_code == exported.status_code == 403
    assert grant.json() == exported.json() == {"detail": "Forbidden"}
    assert database.snapshot() == before


def test_rung_two_forgotten_post_verb_exports_for_non_escalated_agent(
    vulnerable_client: TestClient,
) -> None:
    identity = vulnerable_client.get("/me", headers=auth("demo-agent-two-token"))
    guarded = vulnerable_client.get("/admin/export", headers=auth("demo-agent-two-token"))
    forgotten = vulnerable_client.post("/admin/export", headers=auth("demo-agent-two-token"))
    assert identity.json()["role"] == "agent"
    assert guarded.status_code == 403
    assert forgotten.status_code == 200
    assert len(forgotten.json()) == 2


def test_secure_app_refuses_both_export_verbs(client: TestClient) -> None:
    get_response = client.get("/admin/export", headers=auth("demo-agent-two-token"))
    post_response = client.post("/admin/export", headers=auth("demo-agent-two-token"))
    assert get_response.status_code == post_response.status_code == 403
    assert get_response.json() == post_response.json() == {"detail": "Forbidden"}


def test_rung_three_is_hidden_from_schema_but_stays_live(
    vulnerable_client: TestClient,
) -> None:
    schema = vulnerable_client.get("/openapi.json").json()
    assert "/api/v1/users/{user_id}/role" not in schema["paths"]
    response = vulnerable_client.post(
        "/api/v1/users/agent-2/role",
        headers=auth("demo-agent-two-token"),
        json={"role": "admin"},
    )
    assert response.status_code == 200
    assert response.json()["role"] == "admin"


def test_secure_app_deleted_superseded_route(client: TestClient) -> None:
    response = client.post(
        "/api/v1/users/agent-2/role",
        headers=auth("demo-agent-two-token"),
        json={"role": "admin"},
    )
    assert response.status_code == 404


@pytest.fixture
def application_pair(tmp_path: Path) -> Iterator[tuple[TestClient, TestClient]]:
    secure_app = create_secure_app(str(tmp_path / "secure-parity.db"))
    vulnerable_app = create_vulnerable_app(
        str(tmp_path / "vulnerable-parity.db"), require_acknowledgement=False
    )
    with TestClient(secure_app) as secure, TestClient(vulnerable_app) as vulnerable:
        yield secure, vulnerable


def test_benign_permitted_lifecycle_is_identical(
    application_pair: tuple[TestClient, TestClient],
) -> None:
    secure, vulnerable = application_pair
    requests = [
        ("GET", "/me", "demo-viewer-token", None),
        ("GET", "/tickets", "demo-viewer-token", None),
        (
            "POST",
            "/tickets",
            "demo-agent-token",
            {"subject": "Parity request", "assignee_id": "agent-1"},
        ),
        (
            "POST",
            "/tickets/4/comments",
            "demo-agent-token",
            {"body": "Parity comment"},
        ),
        (
            "POST",
            "/tickets/4/reassign",
            "demo-supervisor-token",
            {"assignee_id": "agent-2"},
        ),
        (
            "POST",
            "/admin/users/viewer-1/role",
            "demo-admin-token",
            {"role": "agent"},
        ),
        ("POST", "/admin/tickets/bulk-close", "demo-admin-token", None),
        ("GET", "/admin/export", "demo-admin-token", None),
        ("POST", "/admin/export", "demo-admin-token", None),
        ("POST", "/admin/customers/customer-1/contact", "demo-admin-token", None),
    ]
    for method, path, token, body in requests:
        secure_response = secure.request(method, path, headers=auth(token), json=body)
        vulnerable_response = vulnerable.request(method, path, headers=auth(token), json=body)
        assert vulnerable_response.status_code == secure_response.status_code
        assert vulnerable_response.json() == secure_response.json()
    assert vulnerable.app.state.database.snapshot() == secure.app.state.database.snapshot()


def test_object_level_refusal_is_identical(application_pair: tuple[TestClient, TestClient]) -> None:
    secure, vulnerable = application_pair
    body = {"body": "Not assigned"}
    secure_response = secure.post(
        "/tickets/2/comments", headers=auth("demo-agent-token"), json=body
    )
    vulnerable_response = vulnerable.post(
        "/tickets/2/comments", headers=auth("demo-agent-token"), json=body
    )
    assert secure_response.status_code == vulnerable_response.status_code == 403
    assert secure_response.json() == vulnerable_response.json() == {"detail": "Forbidden"}


def test_scenario_engine_reports_five_contrasts(
    application_pair: tuple[TestClient, TestClient],
) -> None:
    secure, vulnerable = application_pair
    comparison = run_comparison(secure, vulnerable)
    assert [(result.rung, result.application, result.verdict) for result in comparison.results] == [
        (1, "vulnerable", "VULNERABLE"),
        (1, "secure", "SECURE"),
        (2, "vulnerable", "VULNERABLE"),
        (2, "secure", "SECURE"),
        (3, "vulnerable", "VULNERABLE"),
        (3, "secure", "SECURE"),
        (4, "vulnerable", "VULNERABLE"),
        (4, "secure", "SECURE"),
        (5, "vulnerable", "VULNERABLE"),
        (5, "secure", "SECURE"),
    ]
    rung_one = comparison.results[0]
    assert rung_one.effect == "role agent->admin; export 403->200"
    assert rung_one.attributed_role == "admin"


def test_verbose_cli_render_includes_underlying_http_exchange(
    application_pair: tuple[TestClient, TestClient], capsys: pytest.CaptureFixture[str]
) -> None:
    secure, vulnerable = application_pair
    render(run_comparison(secure, vulnerable), verbose=True)
    output = capsys.readouterr().out
    assert "BFLA comparison" in output
    assert '"method": "POST"' in output
    assert '"path": "/admin/users/agent-1/role"' in output
    assert '"status": 200' in output


def test_compose_declares_two_opt_ins_and_internal_network() -> None:
    compose = Path("compose.yaml").read_text()
    assert 'profiles: ["vulnerable"]' in compose
    assert 'ALLOW_VULNERABLE_DEMO: "${ALLOW_VULNERABLE_DEMO:-false}"' in compose
    assert '"127.0.0.1:8001:8080"' in compose
    assert "internal: true" in compose
