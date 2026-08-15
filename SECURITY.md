# Security policy

## Demonstrated behavior

This repository intentionally contains five function-level authorization failures in the opt-in
vulnerable application. They are the subject of the local educational demonstration, are covered by its
comparison tests and walkthrough, and are not vulnerabilities to report.

The secure application is the default. The vulnerable application requires both its Compose profile and
an explicit acknowledgement, binds only through the fixed loopback gateway, and must never be deployed.
Nothing in this repository is offered as a hosted service or represented as production-ready.

## Reporting an unintended vulnerability

Please use the repository's [private vulnerability reporting form](../../security/advisories/new) for a
security problem outside the intentional demonstration boundary. Do not include real credentials or
personal data, and do not open a public issue for an undisclosed vulnerability.

Include the affected component, a concise reproduction using fictional data, the observed impact, and
any suggested containment. Submission does not promise a response time, fix schedule, support duration,
or compatibility commitment.
