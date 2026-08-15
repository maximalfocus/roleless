from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from roleless.model import Actor, Role

DEMO_TOKENS: dict[str, str] = {
    "demo-viewer-token": "viewer-1",
    "demo-agent-token": "agent-1",
    "demo-agent-two-token": "agent-2",
    "demo-supervisor-token": "supervisor-1",
    "demo-admin-token": "admin-1",
    "demo-contractor-token": "contractor-1",
}

USERS: tuple[tuple[str, str, Role], ...] = (
    ("viewer-1", "Vera Viewer", "viewer"),
    ("agent-1", "Avery Agent", "agent"),
    ("agent-2", "Arden Agent", "agent"),
    ("supervisor-1", "Sam Supervisor", "supervisor"),
    ("admin-1", "Addison Admin", "admin"),
    ("contractor-1", "Casey Contractor", "contractor"),
)

CUSTOMERS: tuple[tuple[str, str, str, str], ...] = (
    ("customer-1", "Example Orchard", "hello@example.invalid", "+1-555-0101"),
    ("customer-2", "Sample Harbor", "support@example.invalid", "+1-555-0102"),
)

TICKETS: tuple[tuple[int, str, str, str], ...] = (
    (1, "Reset fictional portal access", "open", "agent-1"),
    (2, "Explain sample invoice", "open", "agent-2"),
    (3, "Confirm demonstration callback", "closed", "agent-1"),
)


class Database:
    def __init__(self, path: str) -> None:
        self.path = path

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self.connect()
        try:
            connection.execute("BEGIN")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        path = Path(self.path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.unlink(missing_ok=True)
        with self.transaction() as connection:
            connection.executescript(
                """
                CREATE TABLE users (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    role TEXT NOT NULL
                );
                CREATE TABLE customers (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    email TEXT NOT NULL,
                    phone TEXT NOT NULL
                );
                CREATE TABLE tickets (
                    id INTEGER PRIMARY KEY,
                    subject TEXT NOT NULL,
                    status TEXT NOT NULL,
                    assignee_id TEXT NOT NULL REFERENCES users(id)
                );
                CREATE TABLE comments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ticket_id INTEGER NOT NULL REFERENCES tickets(id),
                    author_id TEXT NOT NULL REFERENCES users(id),
                    body TEXT NOT NULL
                );
                """
            )
            connection.executemany("INSERT INTO users VALUES (?, ?, ?)", USERS)
            connection.executemany("INSERT INTO customers VALUES (?, ?, ?, ?)", CUSTOMERS)
            connection.executemany("INSERT INTO tickets VALUES (?, ?, ?, ?)", TICKETS)

    def actor_for_token(self, token: str) -> Actor | None:
        user_id = DEMO_TOKENS.get(token)
        if user_id is None:
            return None
        with self.connect() as connection:
            row = connection.execute(
                "SELECT id, name, role FROM users WHERE id = ?", (user_id,)
            ).fetchone()
        return Actor.model_validate(dict(row)) if row else None

    def list_tickets(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT id, subject, status, assignee_id FROM tickets ORDER BY id"
            ).fetchall()
        return [dict(row) for row in rows]

    def create_ticket(self, subject: str, assignee_id: str) -> dict[str, Any]:
        with self.transaction() as connection:
            cursor = connection.execute(
                "INSERT INTO tickets(subject, status, assignee_id) VALUES (?, 'open', ?)",
                (subject, assignee_id),
            )
            if cursor.lastrowid is None:
                raise RuntimeError("ticket insert returned no identifier")
            ticket_id = int(cursor.lastrowid)
        return self.ticket(ticket_id)

    def ticket(self, ticket_id: int) -> dict[str, Any]:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT id, subject, status, assignee_id FROM tickets WHERE id = ?", (ticket_id,)
            ).fetchone()
        if row is None:
            raise KeyError(ticket_id)
        return dict(row)

    def add_comment(self, ticket_id: int, author_id: str, body: str) -> dict[str, Any]:
        with self.transaction() as connection:
            cursor = connection.execute(
                "INSERT INTO comments(ticket_id, author_id, body) VALUES (?, ?, ?)",
                (ticket_id, author_id, body),
            )
            if cursor.lastrowid is None:
                raise RuntimeError("comment insert returned no identifier")
            comment_id = int(cursor.lastrowid)
        return {"id": comment_id, "ticket_id": ticket_id, "author_id": author_id, "body": body}

    def reassign(self, ticket_id: int, assignee_id: str) -> dict[str, Any]:
        with self.transaction() as connection:
            cursor = connection.execute(
                "UPDATE tickets SET assignee_id = ? WHERE id = ?", (assignee_id, ticket_id)
            )
            if cursor.rowcount != 1:
                raise KeyError(ticket_id)
        return self.ticket(ticket_id)

    def bulk_close(self) -> dict[str, int]:
        with self.transaction() as connection:
            cursor = connection.execute(
                "UPDATE tickets SET status = 'closed' WHERE status = 'open'"
            )
            changed = cursor.rowcount
        return {"closed": changed}

    def grant_role(self, user_id: str, role: Role) -> Actor:
        with self.transaction() as connection:
            cursor = connection.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
            if cursor.rowcount != 1:
                raise KeyError(user_id)
        with self.connect() as connection:
            row = connection.execute(
                "SELECT id, name, role FROM users WHERE id = ?", (user_id,)
            ).fetchone()
        if row is None:
            raise KeyError(user_id)
        return Actor.model_validate(dict(row))

    def export_customers(self) -> list[dict[str, str]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT id, name, email, phone FROM customers ORDER BY id"
            ).fetchall()
        return [dict(row) for row in rows]

    def customer_contact(self, customer_id: str) -> dict[str, str]:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT id, name, email, phone FROM customers WHERE id = ?", (customer_id,)
            ).fetchone()
        if row is None:
            raise KeyError(customer_id)
        return dict(row)

    def snapshot(self) -> dict[str, list[dict[str, Any]]]:
        with self.connect() as connection:
            return {
                "users": [
                    dict(row)
                    for row in connection.execute("SELECT * FROM users ORDER BY id").fetchall()
                ],
                "customers": [
                    dict(row)
                    for row in connection.execute("SELECT * FROM customers ORDER BY id").fetchall()
                ],
                "tickets": [
                    dict(row)
                    for row in connection.execute("SELECT * FROM tickets ORDER BY id").fetchall()
                ],
                "comments": [
                    dict(row)
                    for row in connection.execute("SELECT * FROM comments ORDER BY id").fetchall()
                ],
            }
