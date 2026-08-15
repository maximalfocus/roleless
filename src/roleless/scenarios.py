from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

ACTOR_TOKENS = {
    "agent": "demo-agent-token",
    "agent_two": "demo-agent-two-token",
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
    ) -> httpx.Response:
        headers = {"Authorization": f"Bearer {ACTOR_TOKENS[actor]}"}
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


def run_comparison(secure: httpx.Client, vulnerable: httpx.Client) -> Comparison:
    secure_recorder = Recorder("secure", secure)
    vulnerable_recorder = Recorder("vulnerable", vulnerable)
    results: list[RungResult] = []
    for scenario in (_rung_one, _rung_two, _rung_three):
        results.append(scenario(vulnerable_recorder))
        results.append(scenario(secure_recorder))
    return Comparison(
        results=tuple(results),
        exchanges=tuple(vulnerable_recorder.exchanges + secure_recorder.exchanges),
    )


def run_one(rung: int, application: str, client: httpx.Client) -> Comparison:
    scenarios = {1: _rung_one, 2: _rung_two, 3: _rung_three}
    recorder = Recorder(application, client)
    result = scenarios[rung](recorder)
    return Comparison(results=(result,), exchanges=tuple(recorder.exchanges))
