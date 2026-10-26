.DEFAULT_GOAL := help
VENV ?= .venv
PY := $(VENV)/bin/python

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

install: ## Native install (runtime)
	./scripts/install.sh

dev: ## Native install with test/lint/security tooling
	./scripts/install.sh --dev

lint: ## Ruff lint + format check + shellcheck
	$(VENV)/bin/ruff check . && $(VENV)/bin/ruff format --check . && shellcheck docker/entrypoint.sh scripts/*.sh

format: ## Auto-format the code
	$(VENV)/bin/ruff format . && $(VENV)/bin/ruff check --fix .

test: ## Run the test suite with coverage (fails under 90%)
	$(VENV)/bin/pytest --cov=app --cov-report=term-missing --cov-report=html

security: ## Bandit SAST + pip-audit dependency scan
	$(VENV)/bin/bandit -q -c pyproject.toml -r app && $(VENV)/bin/pip-audit -r requirements.txt

run: ## Start API + dashboard natively
	./scripts/start_native.sh

audit: ## Host audit with JSON/PDF/HTML output (use sudo for full coverage)
	./scripts/run_audit.sh

examples: ## Regenerate docs/examples from the demo scenario
	$(PY) scripts/generate_examples.py

up: ## docker compose up -d
	docker compose up -d

down: ## docker compose down (keeps data)
	docker compose down

sensor: ## Start the optional passive network sensor (Docker)
	docker compose --profile sensor up -d sensor

admin-password: ## Print the generated admin password (Docker)
	@docker compose exec api cat /run/cybershield-secrets/admin_password; echo

uninstall: ## Remove the Docker and/or native install (asks first; ARGS="--dry-run" / "--keep-data")
	./scripts/uninstall.sh $(ARGS)

.PHONY: help install dev lint format test security run audit examples up down sensor admin-password uninstall
