# Missing function-level authorization walkthrough

This is a wholly fictional, local educational demonstration. The intentionally vulnerable application
must not be deployed. It addresses no real organization or API, executes no command, writes nothing to
the host filesystem, and keeps every state change in a disposable in-container SQLite database recreated
on startup. Its network has no external egress.

## The authorization questions

An API has three separate questions to answer:

1. **Identity:** is the caller authenticated?
2. **Function level:** may the caller's stored role invoke this operation?
3. **Object level:** may the caller touch this particular record?

Broken Function Level Authorization (BFLA) is OWASP API5:2023 and an instance of OWASP A01:2021 Broken
Access Control. It maps primarily to CWE-285 (improper authorization), with missing checks represented by
CWE-862. It is also known historically as Missing Function Level Access Control and commonly as vertical
privilege escalation. BOLA is different: BOLA is horizontal access to another user's object at the same
privilege level; BFLA reaches an operation above the caller's privilege level. `roleless` keeps the
object-level rule identical and correct in both applications so only the function-level axis changes.

## Rung 1 — no check at all

An authenticated `agent` calls `POST /admin/users/{id}/role`. The vulnerable handler authenticates the
caller but never asks whether that role may grant roles, so the agent stores `admin` on their own user.
The next identity lookup reports `admin`, and the customer export succeeds under that newly stored role.
The missing check therefore collapses the model rather than exposing only one endpoint. The secure app's
central policy returns a generic `403`, and its independent no-self-elevation rule would also refuse a
genuine admin targeting themselves.

## Rung 2 — the forgotten verb

The vulnerable `GET /admin/export` has a per-handler admin check. A later streaming-style `POST` handler
for the same path forgot it, so a non-escalated agent receives the full fictional customer export through
`POST` while `GET` returns `403`. Authorization belongs to every *(method, route)* pair, not to the visual
shape of a URL. A related failure is guarding a prefix while registering a privileged function outside
that prefix.

## Rung 3 — hidden from documentation, still live

The superseded `POST /api/v1/users/{id}/role` handler is registered with OpenAPI schema generation
disabled. It does not appear in `/openapi.json`, but a direct call still grants the role. Schema
suppression is a presentation setting, never authorization. The secure app deletes the superseded route,
so it returns `404`; its startup completeness check would fail if any surviving route lacked a central
policy declaration.

## Why the secure design closes the class

The secure router looks up every `(method, route)` in one reviewable policy table and grants only explicit
role-to-permission entries. Unknown roles and undeclared routes are refused by default, and application
startup rejects incomplete policy coverage. This turns an author's forgotten decorator into a startup
failure. Allowlisting also means a later-added role receives nothing until intentionally granted. The
separate no-self-elevation rule adds segregation of duties even for genuine admins.

The client receives one non-explanatory `403` body that reveals no required role or permission. A generic
structured audit event records the fictional actor, stored role, attempted function, and refusal on the
server side without tokens, authorization headers, customer contacts, or real personal information.
Returning `404` instead can be appropriate when a route's existence is sensitive; here `403` is accurate
because the declared operations are not secret, only entitlement is restricted.
