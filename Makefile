# Makefile for NIST 800-53 Compliance Scanner (2025 Edition)
# Modern development workflow automation

.PHONY: help install install-dev clean test test-quick lint format type-check security docker-build docker-up docker-down pre-commit

# Default target
.DEFAULT_GOAL := help

# Python and tool configuration
PYTHON := python
PIP := pip
PYTEST := pytest
RUFF := ruff
MYPY := mypy

# Directories
SRC_DIR := modules
TEST_DIR := tests
DOCS_DIR := docs

help: ## Show this help message
	@echo "NIST 800-53 Compliance Scanner - 2025 Edition"
	@echo "=============================================="
	@echo ""
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install the package in production mode
	$(PIP) install --upgrade pip setuptools wheel
	$(PIP) install .

install-dev: ## Install the package in development mode with all dev dependencies
	$(PIP) install --upgrade pip setuptools wheel
	$(PIP) install -e ".[dev]"
	pre-commit install

clean: ## Clean up generated files and caches
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	rm -rf build dist htmlcov .coverage coverage.xml
	@echo "✨ Cleanup complete!"

test: ## Run all tests with coverage
	$(PYTEST) $(TEST_DIR) -v --cov=$(SRC_DIR) --cov-report=term-missing --cov-report=html --cov-report=xml

test-quick: ## Run tests without coverage (faster)
	$(PYTEST) $(TEST_DIR) -v -x

test-watch: ## Run tests in watch mode (requires pytest-watch)
	ptw $(TEST_DIR) -- -v

lint: ## Run linting with Ruff
	$(RUFF) check $(SRC_DIR) $(TEST_DIR)

lint-fix: ## Run linting with Ruff and auto-fix issues
	$(RUFF) check --fix $(SRC_DIR) $(TEST_DIR)

format: ## Format code with Ruff
	$(RUFF) format $(SRC_DIR) $(TEST_DIR)

format-check: ## Check code formatting without making changes
	$(RUFF) format --check $(SRC_DIR) $(TEST_DIR)

type-check: ## Run type checking with mypy
	$(MYPY) $(SRC_DIR) --install-types --non-interactive

security: ## Run security scans (bandit, safety, semgrep)
	@echo "Running Bandit security scanner..."
	bandit -r $(SRC_DIR) -c pyproject.toml
	@echo ""
	@echo "Running Safety dependency checker..."
	safety check --json || true
	@echo ""
	@echo "Running pip-audit..."
	pip-audit --desc || true

pre-commit: ## Run pre-commit hooks on all files
	pre-commit run --all-files

pre-commit-update: ## Update pre-commit hooks to latest versions
	pre-commit autoupdate

docker-build: ## Build Docker image
	docker build -t nist-compliance-scanner:latest .

docker-up: ## Start all services with Docker Compose
	docker-compose up -d

docker-down: ## Stop all services
	docker-compose down

docker-logs: ## View logs from all Docker services
	docker-compose logs -f

docker-clean: ## Clean up Docker containers and volumes
	docker-compose down -v
	docker system prune -f

ci: lint format-check type-check test security ## Run all CI checks locally (lint, format, type-check, test, security)

dev-setup: install-dev pre-commit ## Complete development environment setup
	@echo "✅ Development environment ready!"
	@echo "Run 'make help' to see available commands"

update-deps: ## Update all dependencies to latest versions
	$(PIP) install --upgrade pip setuptools wheel
	$(PIP) install --upgrade -e ".[dev]"
	pre-commit autoupdate

# Documentation targets
docs: ## Build documentation with Sphinx
	cd $(DOCS_DIR) && make html

docs-clean: ## Clean documentation build
	cd $(DOCS_DIR) && make clean

docs-serve: docs ## Build and serve documentation locally
	cd $(DOCS_DIR)/_build/html && $(PYTHON) -m http.server 8080

# Quality metrics
coverage-report: test ## Generate and open HTML coverage report
	@echo "Opening coverage report in browser..."
	$(PYTHON) -m webbrowser htmlcov/index.html

metrics: ## Show code metrics
	@echo "Lines of code:"
	@find $(SRC_DIR) -name "*.py" | xargs wc -l | tail -1
	@echo ""
	@echo "Test coverage:"
	@$(PYTEST) $(TEST_DIR) --cov=$(SRC_DIR) --cov-report=term | grep "TOTAL"

# Development helpers
shell: ## Start Python shell with project context
	$(PYTHON) -i -c "import sys; sys.path.insert(0, '.')"

watch-tests: ## Watch for changes and run tests automatically
	find $(SRC_DIR) $(TEST_DIR) -name "*.py" | entr -c make test-quick

# Version management
version: ## Show current version
	@$(PYTHON) -c "import tomllib; print(tomllib.load(open('pyproject.toml', 'rb'))['project']['version'])"

# Deployment targets
release-check: ci ## Check if ready for release
	@echo "✅ All checks passed! Ready for release."

release-build: clean ## Build distribution packages
	$(PYTHON) -m build
	@echo "✅ Distribution packages built in dist/"

release-test: release-build ## Test release on TestPyPI
	$(PYTHON) -m twine upload --repository testpypi dist/*

release: release-build ## Upload release to PyPI (use with caution!)
	$(PYTHON) -m twine upload dist/*
