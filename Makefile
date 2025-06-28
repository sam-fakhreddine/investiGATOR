.PHONY: help install test lint format clean run-web run-cli setup

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

setup: ## Run initial project setup
	./scripts/setup.sh

install: ## Install dependencies
	poetry install

test: ## Run all tests
	poetry run pytest tests/ -v

test-web: ## Run web interface tests only
	poetry run pytest tests/test_web.py tests/test_web_e2e.py tests/test_web_coverage.py -v

test-web-cov: ## Run web tests with coverage
	poetry run pytest tests/test_web.py tests/test_web_e2e.py tests/test_web_coverage.py -v --cov=vpc_flow_investigator.web --cov-report=html --cov-report=term-missing

test-web-100: ## Verify 100% web test coverage (required for release)
	poetry run pytest tests/test_web.py tests/test_web_e2e.py tests/test_web_coverage.py --cov=vpc_flow_investigator.web --cov-fail-under=100 -q
	@echo "✅ Web interface has 100% test coverage"

lint: ## Run linting
	poetry run flake8 src/
	poetry run mypy src/

format: ## Format code
	poetry run black src/ tests/
	poetry run isort src/ tests/

precommit-install: ## Install pre-commit hooks
	poetry run pre-commit install

precommit-run: ## Run pre-commit hooks on all files
	poetry run pre-commit run --all-files

clean: ## Clean build artifacts
	find . -type d -name __pycache__ -delete
	find . -type f -name "*.pyc" -delete
	rm -rf build/ dist/ *.egg-info/

run-web: ## Start web interface
	poetry run vpc-flow-web

run-cli: ## Show CLI help
	poetry run vpc-flow-investigator

dev: install ## Setup development environment
	@echo "Development environment ready!"
	@echo "Run 'make run-web' to start the web interface"
	@echo "Run 'make run-cli' for CLI usage"