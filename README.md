# roleless

`roleless` is a private, local-only educational project about function-level authorization. The secure
support-desk application binds every API operation to a permission in one central policy table and fails
closed. An intentionally vulnerable companion demonstrates three ways that a function check can be
missing: an unguarded admin function, a forgotten HTTP verb, and an undocumented route that remains live.

All users, tokens, customers, and tickets are fictional demonstration data. The application executes no
commands, accepts no real credentials, and keeps its disposable SQLite state inside the container. The
host needs Docker Compose only; no host Python installation is supported. The vulnerable application is
educational code that must never be deployed or exposed beyond the local demonstration.

## Secure walkthrough

Run the real HTTP walkthrough against fresh fixtures, then remove the disposable container state:

```sh
docker compose --profile demo up --build --abort-on-container-exit --exit-code-from walkthrough
docker compose --profile demo down --volumes
```

The secure API is available during the run at <http://127.0.0.1:8000/docs>. The walkthrough exercises
each legitimate role lifecycle and representative refusals. It should complete well under five minutes
after the images are available.

## Three-rung comparison

Starting the vulnerable application requires two deliberate actions: enable its Compose profile and set
the exact acknowledgement. Run both applications and the deterministic comparison against fresh state:

```sh
ALLOW_VULNERABLE_DEMO=true docker compose --profile vulnerable --profile compare up --build --abort-on-container-exit --exit-code-from compare
docker compose --profile vulnerable --profile compare down --volumes
```

The vulnerable API is then bound only to <http://127.0.0.1:8001>; the secure API remains on
<http://127.0.0.1:8000>. The vulnerable application container remains solely on the internal no-egress
network; a hardened fixed-target loopback gateway publishes port 8001 and can forward only to that
internal service. For detailed request/response output, start the services and run the CLI with
`--verbose`:

```sh
ALLOW_VULNERABLE_DEMO=true docker compose --profile vulnerable up --build --wait
docker compose --profile compare run --rm compare python -m roleless.cli --secure-url http://secure:8000 --vulnerable-url http://vulnerable:8000 --verbose compare
docker compose --profile vulnerable --profile compare down --volumes
```

The CLI also provides an `interactive` subcommand. See [the walkthrough](docs/walkthrough.md) for the
expected results and the lesson carried by each rung.

## Verification

The local and GitHub Actions boundary is the same:

```sh
docker compose --profile verify run --build --rm verify
```

This runs pytest, Ruff, and mypy inside the Python 3.13 container. The default Compose configuration
publishes only the secure service on loopback. The browser console is not part of this slice.

## Authorization model

Authentication answers *who is calling*. Function-level authorization answers *may that stored role call
this operation*. Object-level authorization answers *may the caller act on this record*. Passing the
first and third questions never substitutes for the second.

The secure server reads roles only from its database. `X-Actor-Role` and all other client-provided role
claims are ignored. A single global dependency consults the central `(method, route) -> permission` map,
and startup rejects any non-public route missing from that map. Refusals return the same terse `403`
response; detailed, credential-free evidence is emitted only as a structured audit event.
