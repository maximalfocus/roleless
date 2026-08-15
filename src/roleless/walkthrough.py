from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from typing import Any

import httpx

TOKENS = {
    "viewer": "demo-viewer-token",
    "agent": "demo-agent-token",
    "supervisor": "demo-supervisor-token",
    "admin": "demo-admin-token",
    "contractor": "demo-contractor-token",
}


def headers(role: str, **extra: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {TOKENS[role]}", **extra}


def require(response: httpx.Response, status_code: int) -> Any:
    if response.status_code != status_code:
        raise RuntimeError(f"{response.request.method} {response.request.url}: {response.text}")
    return response.json()


def run(base_url: str) -> None:
    with httpx.Client(base_url=base_url, timeout=10) as client:
        print("roleless secure walkthrough — fresh fictional state")
        for role in ("viewer", "contractor"):
            tickets = require(client.get("/tickets", headers=headers(role)), 200)
            print(f"ALLOW {role:10} tickets:read        rows={len(tickets)}")

        created = require(
            client.post(
                "/tickets",
                headers=headers("agent"),
                json={"subject": "Walkthrough request", "assignee_id": "agent-1"},
            ),
            201,
        )
        require(
            client.post(
                f"/tickets/{created['id']}/comments",
                headers=headers("agent"),
                json={"body": "Walkthrough comment"},
            ),
            201,
        )
        print(f"ALLOW agent      create+comment      ticket={created['id']}")

        reassigned = require(
            client.post(
                f"/tickets/{created['id']}/reassign",
                headers=headers("supervisor"),
                json={"assignee_id": "agent-2"},
            ),
            200,
        )
        print(f"ALLOW supervisor tickets:reassign    assignee={reassigned['assignee_id']}")

        denied = require(
            client.post(
                "/admin/customers/customer-1/contact",
                headers=headers("agent", **{"X-Actor-Role": "admin"}),
            ),
            403,
        )
        print(f"DENY  agent      forged admin header  response={json.dumps(denied)}")

        exported = require(client.post("/admin/export", headers=headers("admin")), 200)
        contact = require(
            client.post("/admin/customers/customer-1/contact", headers=headers("admin")), 200
        )
        closed = require(client.post("/admin/tickets/bulk-close", headers=headers("admin")), 200)
        granted = require(
            client.post(
                "/admin/users/viewer-1/role",
                headers=headers("admin"),
                json={"role": "agent"},
            ),
            200,
        )
        print(
            "ALLOW admin      privileged lifecycle "
            f"customers={len(exported)} contact={contact['id']} "
            f"closed={closed['closed']} granted={granted['role']}"
        )

        self_change = require(
            client.post(
                "/admin/users/admin-1/role",
                headers=headers("admin"),
                json={"role": "viewer"},
            ),
            403,
        )
        print(f"DENY  admin      self elevation rule response={json.dumps(self_change)}")
        print("PASS — secure authorization and legitimate role lifecycle")


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    args = parser.parse_args(argv)
    run(args.base_url)


if __name__ == "__main__":
    main()
