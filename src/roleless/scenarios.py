from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

ACTOR_TOKENS = {
    "agent": "demo-agent-token",
    "agent_two": "demo-agent-two-token",
    "admin": "demo-admin-token",
    "contractor": "demo-contractor-token",
    "viewer": "demo-viewer-token",
}


@dataclass(frozen=True)
class Exchange:
    application: str
    method: str
    path: str
    headers: dict[str, str]
    body: dict[str, str] | None
    status: int
    response: Any


@dataclass(frozen=True)
class RungResult:
    rung: int
    application: str
    actor: str
    attributed_role: str
    function: str
    enforcement: str
    status: str
    effect: str
    verdict: str


@dataclass(frozen=True)
class Comparison:
    results: tuple[RungResult, ...]
    exchanges: tuple[Exchange, ...]


class Recorder:
    def __init__(self, application: str, client: httpx.Client) -> None:
        self.application = application
        self.client = client
        self.exchanges: list[Exchange] = []

    def request(
        self,
        method: str,
        path: str,
        *,
        actor: str,
        body: dict[str, str] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        headers = {"Authorization": f"Bearer {ACTOR_TOKENS[actor]}"}
        headers.update(extra_headers or {})
        response = self.client.request(method, path, headers=headers, json=body)
        try:
            response_body: Any = response.json()
        except ValueError:
            response_body = response.text
        self.exchanges.append(
            Exchange(
                application=self.application,
                method=method,
                path=path,
                headers=headers,
                body=body,
                status=response.status_code,
                response=response_body,
            )
        )
        return response


def _rung_one(recorder: Recorder) -> RungResult:
    role_before = recorder.request("GET", "/me", actor="agent").json()["role"]
    export_before = recorder.request("GET", "/admin/export", actor="agent")
    grant = recorder.request(
        "POST",
        "/admin/users/agent-1/role",
        actor="agent",
        body={"role": "admin"},
    )
    role_after = recorder.request("GET", "/me", actor="agent").json()["role"]
    export_after = recorder.request("POST", "/admin/export", actor="agent")
    vulnerable = (
        grant.status_code == 200 and role_after == "admin" and export_after.status_code == 200
    )
    effect = (
        f"role {role_before}->{role_after}; export "
        f"{export_before.status_code}->{export_after.status_code}"
    )
    return RungResult(
        rung=1,
        application=recorder.application,
        actor="agent-1",
        attributed_role=str(role_after),
        function="POST /admin/users/{id}/role -> POST /admin/export",
        enforcement="no check" if recorder.application == "vulnerable" else "central policy",
        status=f"grant={grant.status_code}, export={export_after.status_code}",
        effect=effect,
        verdict="VULNERABLE" if vulnerable else "SECURE",
    )


def _rung_two(recorder: Recorder) -> RungResult:
    role = recorder.request("GET", "/me", actor="agent_two").json()["role"]
    guarded = recorder.request("GET", "/admin/export", actor="agent_two")
    forgotten = recorder.request("POST", "/admin/export", actor="agent_two")
    vulnerable = guarded.status_code == 403 and forgotten.status_code == 200
    return RungResult(
        rung=2,
        application=recorder.application,
        actor="agent-2",
        attributed_role=str(role),
        function="GET vs POST /admin/export",
        enforcement=(
            "GET per-handler; POST no check"
            if recorder.application == "vulnerable"
            else "central policy"
        ),
        status=f"GET={guarded.status_code}, POST={forgotten.status_code}",
        effect="full customer export"
        if forgotten.status_code == 200
        else "no state or data changed",
        verdict="VULNERABLE" if vulnerable else "SECURE",
    )


def _rung_three(recorder: Recorder) -> RungResult:
    before = recorder.request("GET", "/me", actor="agent_two").json()["role"]
    legacy = recorder.request(
        "POST",
        "/api/v1/users/agent-2/role",
        actor="agent_two",
        body={"role": "admin"},
    )
    after = recorder.request("GET", "/me", actor="agent_two").json()["role"]
    vulnerable = legacy.status_code == 200 and after == "admin"
    return RungResult(
        rung=3,
        application=recorder.application,
        actor="agent-2",
        attributed_role=str(after),
        function="POST /api/v1/users/{id}/role",
        enforcement=(
            "undocumented; no check"
            if recorder.application == "vulnerable"
            else "route deleted; central completeness"
        ),
        status=str(legacy.status_code),
        effect=f"role {before}->{after}",
        verdict="VULNERABLE" if vulnerable else "SECURE",
    )


def _rung_four(recorder: Recorder) -> RungResult:
    agent = recorder.request("POST", "/admin/tickets/bulk-close", actor="agent")
    created = recorder.request(
        "POST",
        "/tickets",
        actor="agent",
        body={"subject": "Denylist demonstration", "assignee_id": "agent-1"},
    )
    contractor = recorder.request("POST", "/admin/tickets/bulk-close", actor="contractor")
    viewer = recorder.request("POST", "/admin/tickets/bulk-close", actor="viewer")
    agent_closed = agent.json().get("closed", 0) if agent.status_code == 200 else 0
    contractor_closed = contractor.json().get("closed", 0) if contractor.status_code == 200 else 0
    vulnerable = (
        agent.status_code == 200
        and agent_closed > 0
        and created.status_code == 201
        and contractor.status_code == 200
        and contractor_closed > 0
        and viewer.status_code == 403
    )
    closed = f"agent={agent_closed}, contractor={contractor_closed}"
    return RungResult(
        rung=4,
        application=recorder.application,
        actor="agent-1 + contractor-1",
        attributed_role="agent + contractor",
        function="POST /admin/tickets/bulk-close",
        enforcement=(
            "deny only viewer"
            if recorder.application == "vulnerable"
            else "central allowlist policy"
        ),
        status=(
            f"agent={agent.status_code}, contractor={contractor.status_code}, "
            f"viewer={viewer.status_code}"
        ),
        effect=f"tickets closed: {closed}",
        verdict="VULNERABLE" if vulnerable else "SECURE",
    )


def _rung_five(recorder: Recorder) -> RungResult:
    stored_role = recorder.request("GET", "/me", actor="agent").json()["role"]
    forged = recorder.request(
        "POST",
        "/admin/customers/customer-1/contact",
        actor="agent",
        extra_headers={"X-Actor-Role": "admin"},
    )
    admin_downgrade = recorder.request(
        "POST",
        "/admin/customers/customer-1/contact",
        actor="admin",
        extra_headers={"X-Actor-Role": "viewer"},
    )
    vulnerable = forged.status_code == 200 and admin_downgrade.status_code == 403
    return RungResult(
        rung=5,
        application=recorder.application,
        actor="agent-1",
        attributed_role=str(stored_role),
        function="POST /admin/customers/{id}/contact",
        enforcement=(
            "trust X-Actor-Role"
            if recorder.application == "vulnerable"
            else "stored role; header ignored"
        ),
        status=(
            f"agent-as-admin={forged.status_code}, admin-as-viewer={admin_downgrade.status_code}"
        ),
        effect="contact returned" if forged.status_code == 200 else "no customer data returned",
        verdict="VULNERABLE" if vulnerable else "SECURE",
    )


def run_comparison(secure: httpx.Client, vulnerable: httpx.Client) -> Comparison:
    secure_recorder = Recorder("secure", secure)
    vulnerable_recorder = Recorder("vulnerable", vulnerable)
    results: list[RungResult] = []
    # Exercise header/denylist rungs before either fictional agent self-promotes.
    for scenario in (_rung_four, _rung_five, _rung_one, _rung_two, _rung_three):
        results.append(scenario(vulnerable_recorder))
        results.append(scenario(secure_recorder))
    return Comparison(
        results=tuple(sorted(results, key=lambda result: result.rung)),
        exchanges=tuple(vulnerable_recorder.exchanges + secure_recorder.exchanges),
    )


def run_one(rung: int, application: str, client: httpx.Client) -> Comparison:
    scenarios = {
        1: _rung_one,
        2: _rung_two,
        3: _rung_three,
        4: _rung_four,
        5: _rung_five,
    }
    recorder = Recorder(application, client)
    result = scenarios[rung](recorder)
    return Comparison(results=(result,), exchanges=tuple(recorder.exchanges))
