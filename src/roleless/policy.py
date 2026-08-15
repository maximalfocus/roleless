from __future__ import annotations

from collections.abc import Mapping

Permission = str
RouteKey = tuple[str, str]

PUBLIC_ROUTES: frozenset[RouteKey] = frozenset(
    {
        ("GET", "/health"),
        ("GET", "/openapi.json"),
        ("GET", "/docs"),
        ("GET", "/docs/oauth2-redirect"),
        ("GET", "/redoc"),
    }
)

ROUTE_PERMISSIONS: dict[RouteKey, Permission] = {
    ("GET", "/me"): "identity:read",
    ("GET", "/tickets"): "tickets:read",
    ("POST", "/tickets"): "tickets:create",
    ("POST", "/tickets/{ticket_id}/comments"): "tickets:comment",
    ("POST", "/tickets/{ticket_id}/reassign"): "tickets:reassign",
    ("POST", "/admin/tickets/bulk-close"): "tickets:bulk-close",
    ("POST", "/admin/users/{user_id}/role"): "users:grant-role",
    ("GET", "/admin/export"): "customers:export",
    ("POST", "/admin/export"): "customers:export",
    ("POST", "/admin/customers/{customer_id}/contact"): "customers:contact:read",
}

ROLE_PERMISSIONS: Mapping[str, frozenset[Permission]] = {
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
