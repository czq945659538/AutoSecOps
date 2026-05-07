.PHONY: help install run test lint fmt clean docker-up docker-down web

help:
	@echo "AutoSecOps — Available commands:"
	@echo "  make install      Install dependencies"
	@echo "  make run           Run Flask web UI (http://localhost:8080)"
	@echo "  make test          Run all tests"
	@echo "  make test-cov     Run tests with coverage report"
	@echo "  make lint          Run code style checks"
	@echo "  make fmt           Format code (ruff/black)"
	@echo "  make clean         Remove build artifacts"
	@echo "  make docker-up     Start all services via Docker Compose"
	@echo "  make docker-down   Stop all Docker Compose services"
	@echo "  make web           Run web UI only (no Docker)"

install:
	pip install -r requirements.txt

run web:
	@echo "Starting AutoSecOps Web UI..."
	FLASK_ENV=development python -m autoops.web.app

test:
	pytest tests/ -v

test-cov:
	pytest tests/ --cov=autoops --cov-report=html --cov-report=term-missing

lint:
	ruff check autoops/

fmt:
	ruff format autoops/ web/

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	rm -rf htmlcov/ .coverage autoops-reports/*

docker-up:
	docker compose up -d
	@echo "Web UI: http://localhost:8080"

docker-down:
	docker compose down
