# TraigentSchema — developer convenience targets.
#
# The headline targets are the local pre-push gate and its installer; they mirror
# the cloud CI gates locally so failures are caught before pushing (see
# docs/LOCAL_CI_GATE.md).

.PHONY: help install local-gate install-hooks lint typecheck test parity format

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

install: ## Install the package with dev extras
	@python -m pip install -e ".[dev]"

local-gate: ## Run the local pre-push gate (ruff + mypy + pytest + parity + spine + sonar-if-main-bound) — RUN THIS BEFORE PUSHING
	@bash scripts/local_gate.sh

install-hooks: ## Install the git pre-push hook (mirrors the cloud gates locally)
	@hooks_dir="$$(git rev-parse --git-path hooks)"; \
	  install -m 0755 hooks/pre-push "$$hooks_dir/pre-push"; \
	  echo "✅ Installed pre-push hook -> $$hooks_dir/pre-push"; \
	  echo "   It runs 'scripts/local_gate.sh' on every push (bypass: git push --no-verify)."

lint: ## ruff check (mirrors ci.yml linting)
	@ruff check traigent_schema/

typecheck: ## mypy (mirrors ci.yml type checking)
	@mypy traigent_schema/ --ignore-missing-imports

test: ## pytest — structural + contract gate (mirrors ci.yml tests)
	@pytest tests/ -q -p no:cacheprovider

parity: ## Verify the parity manifest is up-to-date (mirrors parity-check.yml)
	@python3 scripts/refresh_parity.py --check

format: ## Re-stamp the parity manifest after schema changes (NOT ruff format — CI does not enforce it)
	@python3 scripts/refresh_parity.py --update
