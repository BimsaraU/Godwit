# Godwit. Run `make help` for the list.
#
# Everything here works on a fresh clone with only `uv` and `docker` installed.
# `make test` deliberately does NOT need docker: the golden fixtures are files.

SHELL := /bin/sh
UV := uv
COMPOSE := docker compose -f infra/docker-compose.yml

.DEFAULT_GOAL := help
.PHONY: help install up down logs seed lint fmt type test check clean ci

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

install: ## Create the venv and install every workspace package
	$(UV) sync --all-packages

up: install ## Start Postgres, MinIO and the Iceberg REST catalog, and wait for health
	$(COMPOSE) up -d --wait

down: ## Stop the stack and delete its volumes
	$(COMPOSE) down -v

logs: ## Tail the local stack
	$(COMPOSE) logs -f

seed: install ## Regenerate tests/golden (deterministic; no docker needed)
	$(UV) run python scripts/generate_golden.py

lint: install ## ruff, no autofix
	$(UV) run ruff check .
	$(UV) run ruff format --check .

fmt: install ## ruff, with autofix
	$(UV) run ruff check . --fix
	$(UV) run ruff format .

type: install ## mypy --strict over every package's src
	$(UV) run mypy packages scripts

test: install ## pytest across the whole workspace
	$(UV) run pytest

check: lint type test ## Everything CI runs

ci: check ## Alias for check

clean: ## Remove caches and build artefacts
	rm -rf .mypy_cache .ruff_cache .pytest_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
