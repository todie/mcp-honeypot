# Contributing to MCP Honeypot

Thanks for your interest in contributing! This document covers guidelines for
submitting changes to the project.

## Getting Started

```bash
make setup    # creates .env, venv, installs dependencies
make test     # runs full test suite
make lint     # ruff + pyright
make help     # see all available targets
```

## Development Workflow

1. **Fork and clone** the repository.
2. **Create a feature branch** from `main`:
   ```bash
   git checkout -b feat/your-feature
   ```
3. **Make your changes** — keep commits focused and atomic.
4. **Run checks locally** before pushing:
   ```bash
   make check   # lint + typecheck + test
   ```
5. **Open a pull request** against `main`.

## Code Style

- **Python 3.12** — use modern syntax (`match`, `type` aliases, `X | Y` unions).
- **Formatting**: `ruff format` (100-char line length).
- **Linting**: `ruff check` with security rules enabled (flake8-bandit).
- **Type checking**: `pyright` in basic mode.
- **Pre-commit hooks**: install with `pre-commit install` — runs ruff, pyright,
  gitleaks, hadolint, and yamllint automatically.

## Commit Messages

Use short, imperative-mood subjects:

```
Add OpenAPI spec parser for dynamic tool generation
Fix session ID derivation for IPv6 clients
Update Grafana dashboard to show provider health
```

No conventional-commits prefix required, but be descriptive.

## Testing

- **All new code must have tests.** Aim for the same coverage level or better.
- Use pytest markers to categorize:
  - `@pytest.mark.unit` — pure logic, no external deps
  - `@pytest.mark.module` — server modules (may import OTel/structlog)
  - `@pytest.mark.tools` — CLI tools and test harness
  - `@pytest.mark.integration` — requires live Docker Compose stack
- Run a specific tier: `pytest tests/ -m unit`

## Pull Request Guidelines

- Fill out the PR template (summary, test plan).
- Keep PRs focused — one feature or fix per PR.
- Ensure CI passes (lint, typecheck, all test tiers, secrets scan, Docker build).
- Update docs if you change config vars, CLI flags, or public interfaces.

## Security

- **Never commit real secrets**, even in tests. Use fake/placeholder values.
- The honeypot intentionally returns fake data — that is not a bug.
- See [SECURITY.md](SECURITY.md) for the vulnerability disclosure policy.

## License

By contributing, you agree that your contributions will be licensed under the
project's [MIT License](LICENSE).
