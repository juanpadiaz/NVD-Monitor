.PHONY: help install install-dev test clean lint format type-check security-check docs build docker run-docker stop-docker logs

# Default target
help:
	@echo "Available commands:"
	@echo "  install       - Install for production"
	@echo "  install-dev   - Install for development"
	@echo "  test          - Run all tests"
	@echo "  lint          - Run linting"
	@echo "  format        - Format code"
	@echo "  type-check    - Run type checking"
	@echo "  security-check - Run security checks"
	@echo "  clean         - Clean build artifacts"
	@echo "  docs          - Generate documentation"
	@echo "  build         - Build package"
	@echo "  docker        - Build Docker image"
	@echo "  run-docker    - Run with Docker Compose"
	@echo "  stop-docker   - Stop Docker Compose"
	@echo "  logs          - View Docker logs"

install:
	@echo "Installing NVD Monitor for production..."
	sudo bash install.sh

install-dev:
	@echo "Installing development dependencies..."
	python -m pip install --upgrade pip
	pip install -e ".[dev]"
	pip install -r requirements-dev.txt
	pre-commit install

test:
	@echo "Running tests..."
	pytest tests/ -v --cov=src --cov-report=term-missing --cov-report=html

test-unit:
	@echo "Running unit tests..."
	pytest tests/unit/ -v

test-integration:
	@echo "Running integration tests..."
	pytest tests/integration/ -v

lint:
	@echo "Running linting..."
	pylint src/ tests/
	flake8 src/ tests/

format:
	@echo "Formatting code..."
	black src/ tests/
	isort src/ tests/

format-check:
	@echo "Checking code format..."
	black --check src/ tests/
	isort --check-only src/ tests/

type-check:
	@echo "Running type checking..."
	mypy src/

security-check:
	@echo "Running security checks..."
	bandit -r src/
	safety check

docs:
	@echo "Generating documentation..."
	sphinx-build -b html docs/ docs/_build/html

clean:
	@echo "Cleaning build artifacts..."
	rm -rf build/
	rm -rf dist/
	rm -rf src/*.egg-info/
	rm -rf htmlcov/
	rm -rf .coverage
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	find . -type d -name __pycache__ -delete
	find . -type f -name "*.pyc" -delete

build:
	@echo "Building package..."
	python -m build

docker:
	@echo "Building Docker image..."
	docker build -t nvd-monitor:latest .

run-docker:
	@echo "Starting Docker Compose..."
	docker-compose up -d

stop-docker:
	@echo "Stopping Docker Compose..."
	docker-compose down

logs:
	@echo "Viewing Docker logs..."
	docker-compose logs -f nvd-monitor

# Development workflow
dev-setup: install-dev
	@echo "Development environment ready!"

dev-test: format lint type-check test
	@echo "All development checks passed!"

ci: format-check lint type-check security-check test
	@echo "CI pipeline completed!"

# Release workflow
release-check: ci docs build
	@echo "Release checks completed!"

# Quick commands
quick-test:
	pytest tests/unit/ -x -v

quick-lint:
	flake8 src/ --select=E9,F63,F7,F82

# Database commands
db-setup:
	@echo "Setting up test database..."
	mysql -u root -p -e "CREATE DATABASE IF NOT EXISTS nvd_monitor_test;"

db-migrate:
	@echo "Running database migrations..."
	python -c "from src.nvd_monitor.database import migrate; migrate()"

# Monitoring commands
status:
	nvd-status

monitor-test:
	nvd-monitor --run-once

admin:
	nvd-admin test-all
