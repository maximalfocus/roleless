from __future__ import annotations

import json
import os
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated, Any, cast

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.routing import APIRoute

from roleless.database import Database
from roleless.model import Actor, CommentCreate, ReassignRequest, RoleGrant, TicketCreate
from roleless.policy import PUBLIC_ROUTES, ROLE_PERMISSIONS, ROUTE_PERMISSIONS, RouteKey

FORBIDDEN = HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
UNAUTHORIZED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Unauthorized",
    headers={"WWW-Authenticate": "Bearer"},
)


def route_key(request: Request) -> RouteKey:
    route = request.scope.get("route")
    path = getattr(route, "path", request.url.path)
    return request.method.upper(), str(path)


def authenticate(request: Request) -> Actor:
    authorization = request.headers.get("Authorization", "")
    scheme, separator, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not separator or not token or " " in token:
        raise UNAUTHORIZED
    actor = database_for(request).actor_for_token(token)
    if actor is None:
        raise UNAUTHORIZED
    return actor


def audit_refusal(request: Request, actor: Actor, function: RouteKey, permission: str) -> None:
    event = {
        "event": "function_authorization",
        "request_id": request.headers.get("X-Request-ID") or str(uuid.uuid4()),
        "actor_id": actor.id,
        "actor_role": actor.role,
        "function": f"{function[0]} {function[1]}",
        "required_permission": permission,
        "outcome": "refused",
    }
    print(json.dumps(event, separators=(",", ":"), sort_keys=True), flush=True)


def refuse(request: Request, actor: Actor, permission: str) -> None:
    audit_refusal(request, actor, route_key(request), permission)
    raise FORBIDDEN


def enforce_authorization(request: Request) -> None:
    key = route_key(request)
    if key in PUBLIC_ROUTES:
        return
    actor = authenticate(request)
    request.state.actor = actor
    permission = ROUTE_PERMISSIONS.get(key)
    if permission is None or permission not in ROLE_PERMISSIONS.get(actor.role, frozenset()):
        audit_refusal(request, actor, key, permission or "undeclared")
        raise FORBIDDEN


def current_actor(request: Request) -> Actor:
    return cast(Actor, request.state.actor)


ActorDependency = Annotated[Actor, Depends(current_actor)]


def database_for(request: Request) -> Database:
    return cast(Database, request.app.state.database)


def validate_policy_completeness(app: FastAPI) -> None:
    declared_routes: set[RouteKey] = set()
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        for method in route.methods:
            key = method.upper(), route.path
            if key not in PUBLIC_ROUTES:
                declared_routes.add(key)
    missing = declared_routes - ROUTE_PERMISSIONS.keys()
    stale = ROUTE_PERMISSIONS.keys() - declared_routes
    if missing or stale:
        raise RuntimeError(
            f"policy table mismatch: missing={sorted(missing)!r}, stale={sorted(stale)!r}"
        )


def create_app(database_path: str | None = None) -> FastAPI:
    path: str = (
        database_path
        if database_path is not None
        else os.environ.get("ROLELESS_DB_PATH", "/tmp/roleless/roleless.db")
    )
    database = Database(path)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        validate_policy_completeness(app)
        database.initialize()
        yield

    application = FastAPI(
        title="roleless secure support desk",
        version="0.1.0",
        dependencies=[Depends(enforce_authorization)],
        lifespan=lifespan,
    )
    application.state.database = database

    @application.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @application.get("/me")
    def me(actor: ActorDependency) -> Actor:
        return actor

    @application.get("/tickets")
    def tickets(request: Request) -> list[dict[str, Any]]:
        return database_for(request).list_tickets()

    @application.post("/tickets", status_code=status.HTTP_201_CREATED)
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

    @application.post("/tickets/{ticket_id}/comments", status_code=status.HTTP_201_CREATED)
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
        try:
            return database.add_comment(ticket_id, actor.id, body.body)
        except KeyError as error:
            raise HTTPException(status_code=404, detail="Not Found") from error

    @application.post("/tickets/{ticket_id}/reassign")
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

    @application.post("/admin/tickets/bulk-close")
    def bulk_close(request: Request, actor: ActorDependency) -> dict[str, int]:
        del actor
        return database_for(request).bulk_close()

    @application.post("/admin/users/{user_id}/role")
    def grant_role(
        user_id: str, body: RoleGrant, request: Request, actor: ActorDependency
    ) -> Actor:
        if user_id == actor.id:
            refuse(request, actor, "users:grant-role:self-prohibited")
        try:
            return database_for(request).grant_role(user_id, body.role)
        except KeyError as error:
            raise HTTPException(status_code=404, detail="Not Found") from error

    def export(request: Request) -> list[dict[str, str]]:
        return database_for(request).export_customers()

    application.get("/admin/export")(export)
    application.post("/admin/export")(export)

    @application.post("/admin/customers/{customer_id}/contact")
    def contact(customer_id: str, request: Request, actor: ActorDependency) -> dict[str, str]:
        del actor
        try:
            return database_for(request).customer_contact(customer_id)
        except KeyError as error:
            raise HTTPException(status_code=404, detail="Not Found") from error

    return application


app = create_app()
