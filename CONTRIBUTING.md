# Contributing

`roleless` welcomes focused improvements to its local educational demonstration. Keep every user,
token, customer, ticket, and endpoint fictional. Do not add real targets, credentials, hosted services,
cloud deployment, general-purpose request forwarding, host filesystem writes, or external network
access.

## Development workflow

The supported host dependency is Docker Compose. Fork the repository, create a focused branch, and keep
each change small enough to review as one outcome. Update tests and maintained documentation when
observable behavior changes.

Run the same containerized gate used by continuous integration:

```sh
docker compose --profile verify run --build --rm verify
```

For changes to runtime behavior, also exercise the affected documented walkthrough from fresh container
state. Changes to the intentionally vulnerable application must preserve both explicit opt-in controls,
loopback-only publication, and its hardened no-egress container boundary.

Open a pull request describing the outcome, verification performed, and any deliberately excluded
follow-up. Participation does not imply a response-time, long-term support, compatibility, or
production-readiness commitment.

For an unintended security problem, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.
