# Security Policy

## Scope

MCP Honeypot is a **research honeypot** that intentionally exposes fake tools
and returns fabricated responses. This deceptive behaviour is by design and
does not constitute a vulnerability.

Vulnerabilities in scope include:
- Bugs that allow an attacker to execute real commands on the host
- Leaks of actual secrets, credentials, or host information
- Bypasses that expose the internal telemetry pipeline to untrusted parties
- Denial-of-service vectors that crash the honeypot or its observability stack

Out of scope:
- The honeypot returning fake data (that is its purpose)
- Detection logic gaps (file an issue instead)

## Reporting a Vulnerability

Please report security issues via
[GitHub Security Advisories](https://github.com/todie/mcp-honeypot/security/advisories/new)
or email **security@todie.dev**.

- Do **not** open a public issue for security vulnerabilities.
- You will receive an acknowledgement within 48 hours.
- We aim to release a fix within 7 days of confirmation.

## Supported Versions

Only the latest release on the `main` branch is supported.
