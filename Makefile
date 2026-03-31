.DEFAULT_GOAL := help
SHELL := /bin/bash

# ── Meta ──────────────────────────────────────────────────────────────────────

.PHONY: help
help: ## Show this help
	@printf '\nUsage: make \033[36m<target>\033[0m\n\n'
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""

# ── Setup ─────────────────────────────────────────────────────────────────────

.PHONY: setup
setup: ## Create .env, venv, install deps
	@./scripts/setup.sh

.PHONY: venv
venv: ## Create Python venv only (no .env copy)
	@test -d .venv || python3.12 -m venv .venv
	@.venv/bin/pip install --quiet --upgrade pip
	@.venv/bin/pip install --quiet -r server/requirements.txt
	@echo "==> venv ready: source .venv/bin/activate"

# ── Quality ───────────────────────────────────────────────────────────────────

.PHONY: lint
lint: ## Run ruff lint + format check + pyright
	@./scripts/lint.sh

.PHONY: fmt
fmt: ## Auto-fix lint issues and format code
	ruff check --fix server/ tests/
	ruff format server/ tests/

.PHONY: test
test: ## Run pytest unit tests (no Docker)
	@./scripts/test.sh

.PHONY: check
check: lint test ## Run lint + test (full local CI)

.PHONY: secrets
secrets: ## Scan for leaked secrets (gitleaks)
	gitleaks detect --source . --verbose

.PHONY: pre-commit
pre-commit: ## Run all pre-commit hooks on all files
	pre-commit run --all-files

# ── Docker ────────────────────────────────────────────────────────────────────

.PHONY: build
build: ## Build server Docker image
	@./scripts/build.sh

.PHONY: up
up: ## Start full stack (Docker Compose)
	@./scripts/up.sh

.PHONY: down
down: ## Stop stack (preserve volumes)
	@./scripts/down.sh

.PHONY: down-clean
down-clean: ## Stop stack and remove volumes
	@./scripts/down.sh --clean

.PHONY: logs
logs: ## Tail all container logs
	docker compose logs -f

.PHONY: ps
ps: ## Show running containers
	docker compose ps

.PHONY: restart
restart: down up ## Restart the full stack

# ── Testing ───────────────────────────────────────────────────────────────────

.PHONY: test-unit
test-unit: ## Run fast unit tests only (~135 tests)
	PYTHONPATH=server pytest tests/ -m unit -v --tb=short

.PHONY: test-module
test-module: ## Run server module tests (~50 tests)
	PYTHONPATH=server pytest tests/ -m module -v --tb=short

.PHONY: test-tools
test-tools: ## Run tool/harness tests (~50 tests)
	PYTHONPATH=server pytest tests/ -m tools -v --tb=short

.PHONY: test-all
test-all: ## Run all tests (unit + module + tools)
	@./scripts/test.sh

.PHONY: smoke
smoke: ## Run smoke tests (stack must be running)
	@./scripts/smoke.sh

.PHONY: ci
ci: lint test secrets build ## Full CI pipeline locally

.PHONY: release
release: ## Create a release (usage: make release BUMP=patch)
	@./scripts/release.sh $(BUMP)

.PHONY: version
version: ## Show current version
	@cat VERSION

# ── Admin ─────────────────────────────────────────────────────────────────────

.PHONY: protect
protect: ## Apply branch protection to main
	@./scripts/protect-main.sh

.PHONY: clean
clean: ## Remove build artifacts (.pyc, caches, egg-info)
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .ruff_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .mypy_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name '*.egg-info' -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete 2>/dev/null || true
	@echo "==> Cleaned"
