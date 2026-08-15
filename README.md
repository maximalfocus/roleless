# roleless

`roleless` is a private, local-only educational project about function-level authorization. This first
slice contains only the secure support-desk application: every API operation is bound to a permission in
one central policy table and requests fail closed when the caller's stored role lacks that permission.

All users, tokens, customers, and tickets are fictional demonstration data. The application executes no
commands, accepts no real credentials, and keeps its disposable SQLite state inside the container. The
host needs Docker Compose only; no host Python installation is supported.

## Secure walkthrough

Run the real HTTP walkthrough against fresh fixtures, then remove the disposable container state:

```sh
docker compose --profile demo up --build --abort-on-container-exit --exit-code-from walkthrough
docker compose down --volumes
```

The secure API is available during the run at <http://127.0.0.1:8000/docs>. The walkthrough exercises
each legitimate role lifecycle and representative refusals. It should complete well under five minutes
after the images are available.

## Verification

The local and GitHub Actions boundary is the same:

```sh
docker compose --profile verify run --build --rm verify
```

This runs pytest, Ruff, and mypy inside the Python 3.13 container. The default Compose configuration
publishes only the secure service on loopback. There is no vulnerable application or browser console in
this slice.

## Authorization model

Authentication answers *who is calling*. Function-level authorization answers *may that stored role call
this operation*. Object-level authorization answers *may the caller act on this record*. Passing the
first and third questions never substitutes for the second.

The secure server reads roles only from its database. `X-Actor-Role` and all other client-provided role
claims are ignored. A single global dependency consults the central `(method, route) -> permission` map,
and startup rejects any non-public route missing from that map. Refusals return the same terse `403`
response; detailed, credential-free evidence is emitted only as a structured audit event.
