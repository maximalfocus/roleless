from __future__ import annotations

import os
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, status

from roleless.cors import add_console_cors
from roleless.database import Database
from roleless.model import Actor, CommentCreate, ReassignRequest, RoleGrant, TicketCreate
from roleless.policy import PUBLIC_ROUTES
from roleless.secure import (
    FORBIDDEN,
    ActorDependency,
    authenticate,
    database_for,
    route_key,
)

ACKNOWLEDGEMENT = "ALLOW_VULNERABLE_DEMO"


def authenticate_request(request: Request) -> None:
    if route_key(request) in PUBLIC_ROUTES:
        return
    request.state.actor = authenticate(request)


def require_roles(*allowed_roles: str) -> Callable[[ActorDependency], None]:
    def check(actor: ActorDependency) -> None:
        if actor.role not in allowed_roles:
            raise FORBIDDEN

    return check


require_agent = require_roles("agent", "supervisor", "admin")
require_supervisor = require_roles("supervisor", "admin")
require_admin = require_roles("admin")


def create_app(
    database_path: str | None = None, *, require_acknowledgement: bool = True
) -> FastAPI:
    path: str = (
        database_path
        if database_path is not None
        else os.environ.get("ROLELESS_DB_PATH", "/tmp/roleless/roleless.db")
    )
    database = Database(path)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        del app
        if require_acknowledgement and os.environ.get(ACKNOWLEDGEMENT) != "true":
            raise RuntimeError(
                "vulnerable demo refused to start: set ALLOW_VULNERABLE_DEMO=true explicitly"
            )
        database.initialize()
        yield

    application = FastAPI(
        title="roleless intentionally vulnerable support desk",
        description="Local educational code. Do not deploy.",
        version="0.2.0",
        dependencies=[Depends(authenticate_request)],
        lifespan=lifespan,
    )
    application.state.database = database
    add_console_cors(application)

    @application.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @application.get("/me")
    def me(actor: ActorDependency) -> Actor:
        return actor

    @application.get("/tickets")
    def tickets(request: Request) -> list[dict[str, Any]]:
        return database_for(request).list_tickets()

    @application.post(
        "/tickets", status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_agent)]
    )
    def create_ticket(
        body: TicketCreate, request: Request, actor: ActorDependency
    ) -> dict[str, Any]:
        del actor
        try:
            return database_for(request).create_ticket(body.subject, body.assignee_id)
        except Exception as error:
            if "FOREIGN KEY constraint failed" in str(error):
                raise HTTPException(status_code=409, detail="Conflict") from error
            raise

    @application.post(
        "/tickets/{ticket_id}/comments",
        status_code=status.HTTP_201_CREATED,
        dependencies=[Depends(require_agent)],
    )
    def comment(
        ticket_id: int, body: CommentCreate, request: Request, actor: ActorDependency
    ) -> dict[str, Any]:
        database = database_for(request)
        try:
            ticket = database.ticket(ticket_id)
        except KeyError as error:
            raise HTTPException(status_code=404, detail="Not Found") from error
        if actor.role == "agent" and ticket["assignee_id"] != actor.id:
            raise FORBIDDEN
        return database.add_comment(ticket_id, actor.id, body.body)

    @application.post("/tickets/{ticket_id}/reassign", dependencies=[Depends(require_supervisor)])
    def reassign(
        ticket_id: int, body: ReassignRequest, request: Request, actor: ActorDependency
    ) -> dict[str, Any]:
        del actor
        try:
            return database_for(request).reassign(ticket_id, body.assignee_id)
        except KeyError as error:
            raise HTTPException(status_code=404, detail="Not Found") from error
        except Exception as error:
            if "FOREIGN KEY constraint failed" in str(error):
                raise HTTPException(status_code=409, detail="Conflict") from error
            raise

    # Rung 4: the denylist predates contractor and refuses only the one known read-only role.
    @application.post("/admin/tickets/bulk-close")
    def bulk_close(request: Request, actor: ActorDependency) -> dict[str, int]:
        if actor.role == "viewer":
            raise FORBIDDEN
        return database_for(request).bulk_close()

    # Rung 1: authentication is present, but no function-level authorization exists.
    @application.post("/admin/users/{user_id}/role")
    def grant_role(
        user_id: str, body: RoleGrant, request: Request, actor: ActorDependency
    ) -> Actor:
        del actor
        try:
            return database_for(request).grant_role(user_id, body.role)
        except KeyError as error:
            raise HTTPException(status_code=404, detail="Not Found") from error

    # Rung 2: the original GET is guarded, while the later POST forgot the same check.
    @application.get("/admin/export", dependencies=[Depends(require_admin)])
    def guarded_export(request: Request) -> list[dict[str, str]]:
        return database_for(request).export_customers()

    @application.post("/admin/export")
    def forgotten_post_export(request: Request) -> list[dict[str, str]]:
        return database_for(request).export_customers()

    # Rung 5: the service trusts a gateway-supplied header that the caller can set directly.
    @application.post("/admin/customers/{customer_id}/contact")
    def contact(customer_id: str, request: Request, actor: ActorDependency) -> dict[str, str]:
        claimed_role = request.headers.get("X-Actor-Role", actor.role)
        if claimed_role != "admin":
            raise FORBIDDEN
        try:
            return database_for(request).customer_contact(customer_id)
        except KeyError as error:
            raise HTTPException(status_code=404, detail="Not Found") from error

    # Rung 3: schema suppression hides documentation only; the unguarded route stays live.
    @application.post("/api/v1/users/{user_id}/role", include_in_schema=False)
    def superseded_grant_role(
        user_id: str, body: RoleGrant, request: Request, actor: ActorDependency
    ) -> Actor:
        del actor
        try:
            return database_for(request).grant_role(user_id, body.role)
        except KeyError as error:
            raise HTTPException(status_code=404, detail="Not Found") from error

    return application


app = create_app()
