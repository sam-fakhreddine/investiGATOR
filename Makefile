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

test: ## Run tests
	poetry run pytest tests/

lint: ## Run linting
	poetry run flake8 src/
	poetry run mypy src/

format: ## Format code
	poetry run black src/ tests/
	poetry run isort src/ tests/

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