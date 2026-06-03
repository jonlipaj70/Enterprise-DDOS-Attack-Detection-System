# ============================================================
# DDoS Detection System — Makefile
# ============================================================

.PHONY: help install dev run test lint format clean docker-build docker-up docker-down

PYTHON = python
PIP = pip
PYTEST = pytest

help: ## Show this help message
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install production dependencies
	$(PIP) install -r requirements.txt

dev: ## Install development dependencies
	$(PIP) install -e ".[dev]"

run: ## Run the full system (API + Dashboard)
	$(PYTHON) -m src.api.server

run-api: ## Run only the API server
	uvicorn src.api.server:app --host 0.0.0.0 --port 8000 --reload

run-dashboard: ## Serve the dashboard
	$(PYTHON) -m http.server 8080 --directory dashboard

test: ## Run all tests
	$(PYTEST) tests/ -v --cov=src --cov-report=term-missing

test-unit: ## Run unit tests only
	$(PYTEST) tests/unit/ -v

test-integration: ## Run integration tests
	$(PYTEST) tests/integration/ -v -m integration

test-performance: ## Run performance tests
	$(PYTEST) tests/performance/ -v -m performance

lint: ## Run linters
	flake8 src/ tests/
	mypy src/

format: ## Format code
	black src/ tests/
	isort src/ tests/

clean: ## Clean build artifacts
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	rm -rf build/ dist/ *.egg-info .pytest_cache .mypy_cache htmlcov .coverage

docker-build: ## Build Docker images
	docker-compose -f deploy/docker/docker-compose.yml build

docker-up: ## Start Docker containers
	docker-compose -f deploy/docker/docker-compose.yml up -d

docker-down: ## Stop Docker containers
	docker-compose -f deploy/docker/docker-compose.yml down

k8s-deploy: ## Deploy to Kubernetes
	kubectl apply -f deploy/kubernetes/namespace.yaml
	kubectl apply -f deploy/kubernetes/configmap.yaml
	kubectl apply -f deploy/kubernetes/secrets.yaml
	kubectl apply -f deploy/kubernetes/

helm-install: ## Install Helm chart
	helm install ddos-detector deploy/helm/ -f deploy/helm/values.yaml

helm-upgrade: ## Upgrade Helm release
	helm upgrade ddos-detector deploy/helm/ -f deploy/helm/values.yaml
