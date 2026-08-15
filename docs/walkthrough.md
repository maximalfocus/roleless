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
CWE-862; checked-but-wrong decisions map to CWE-863 (incorrect authorization), and the self-promotion
impact illustrates CWE-269 (improper privilege management). It is also known historically as Missing
Function Level Access Control and commonly as vertical privilege escalation. BOLA is different: BOLA is
horizontal access to another user's object at the same privilege level; BFLA reaches an operation above
the caller's privilege level. `roleless` keeps the object-level rule identical and correct in both
applications so only the function-level axis changes.

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

## Rung 4 — a denylist that ages badly

The vulnerable bulk-close handler asks only `if role == "viewer": deny`. An `agent` therefore closes every
open ticket despite lacking that capability. So does `contractor`, a read-only role added after the check
was written and therefore absent from its author's list of known-dangerous roles; only `viewer` is
refused. A denylist encodes what the author happened to know when it was written. The secure allowlist
encodes intent: both low-privilege roles remain denied until someone explicitly grants the permission.

## Rung 5 — client-asserted role

The vulnerable contact handler trusts `X-Actor-Role`, presented as a header an internal gateway was
expected to set and strip. A stored-role `agent` sends `X-Actor-Role: admin` and receives the fictional
customer contact. A genuine admin sending `X-Actor-Role: viewer` is refused by the vulnerable handler,
showing that it trusts the header in both directions. The secure app ignores the header, refuses the
agent, and permits the admin. Any authorization value the client can set is an input, not a fact, unless
it arrives inside something the server itself verifies.

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

## Browser console: hidden is not forbidden

Start the default secure application and static console:

```sh
docker compose up --build --wait
```

Open <http://127.0.0.1:8080>. Select a fictional role and the secure application. The page asks `GET
/me` what role the server has stored, renders the intended function inventory, and hides the
administrative controls unless that response says `admin`. This is presentation only. It is deliberately
not asserted as a security property: a caller can still construct the request that the hidden control
would have sent.

The **Send it anyway** panel exposes each of the five exact demonstration requests and prints its method,
path, fictional authorization header, optional role header, body, and raw HTTP status/body. The secure
results are `403` for rungs 1, 2, 4, and 5 and `404` for the deleted legacy route in rung 3.

To retain those secure results on screen and compare the vulnerable application, start the opt-in profile
in another terminal, select the vulnerable application, and send the same action:

```sh
ALLOW_VULNERABLE_DEMO=true docker compose --profile vulnerable up --build --wait
```

The vulnerable result is `200` with the fictional impact. Rung 1 changes the selected agent's stored role,
so restart with fresh state before demonstrating later rungs as a non-escalated agent. When finished:

```sh
docker compose --profile vulnerable down --volumes --remove-orphans
```

The static page contains a closed allowlist of only `http://127.0.0.1:8000` and
`http://127.0.0.1:8001`; there is no arbitrary target field, third-party asset, build step, service worker,
or persistent storage. Both APIs return cross-origin sharing headers only to the console origin
`http://127.0.0.1:8080`, for the methods and headers the page needs. CORS is a browser sharing rule, not
authorization: non-browser callers do not rely on it, and the server must enforce every function call
regardless of origin.
