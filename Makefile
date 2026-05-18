# ── Variables ───────────────────────────────────────────────────────────────
COMMIT       := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BRANCH       := $(shell git branch --show-current 2>/dev/null || echo "detached")
TIMESTAMP    := $(shell date +%Y%m%d_%H%M%S)
TAG          := $(TIMESTAMP)_$(COMMIT)

CHECKPOINT_DIR := .local_benchmark/checkpoints
CORPUS_DIR     := .local_benchmark/corpus
EVAL_DIR       := evals/skills

CONTAINER_NAME := skill-scanner-api
IMAGE_FILE     := skill-scanner-linux-amd64.tar
ENV_FILE       := .env

# ── Phony targets ──────────────────────────────────────────────────────────
.PHONY: help benchmark benchmark-eval benchmark-corpus test lint clean \
        docker-build docker-load docker-deploy docker-run docker-stop \
        docker-logs docker-shell docker-clean \
        docker-compose-up docker-compose-down

help: ## Show this help
	@echo ""
	@echo "\033[1mSkill Scanner Makefile\033[0m"
	@echo ""
	@echo "\033[1mTargets:\033[0m"
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "\033[1mUsage:\033[0m"
	@echo "  \033[33mmake docker-build\033[0m             # 本地构建镜像"
	@echo "  \033[33mmake docker-deploy\033[0m            # 一键部署 (默认 8081 端口)"
	@echo "  \033[33mmake docker-deploy PORT=9090\033[0m   # 指定端口部署"
	@echo "  \033[33mmake docker-deploy WORKERS=8\033[0m   # 指定 worker 数量"
	@echo "  \033[33mmake docker-save\033[0m              # 导出镜像为 tar (离线部署用)"
	@echo "  \033[33mmake docker-load\033[0m              # 从 tar 加载镜像"
	@echo "  \033[33mmake test\033[0m                     # 运行测试"
	@echo "  \033[33mmake lint\033[0m                     # 代码检查 + 格式化"
	@echo "  \033[33mmake benchmark\033[0m                # 运行完整基准测试"
	@echo ""

# ── Benchmark suite ────────────────────────────────────────────────────────
benchmark: benchmark-eval benchmark-corpus ## Run full benchmark suite

benchmark-eval: ## Run eval-skills benchmark (~30 s)
	@mkdir -p $(CHECKPOINT_DIR)
	@echo "╭─ eval benchmark  [$(TAG)] ─╮"
	uv run python evals/runners/benchmark_runner.py \
		--eval-dir $(EVAL_DIR) \
		--output $(CHECKPOINT_DIR)/$(TAG)_eval.json
	@echo "╰─ saved → $(CHECKPOINT_DIR)/$(TAG)_eval.json ─╯"

benchmark-corpus: ## Run corpus policy benchmark (~9 min)
	@mkdir -p $(CHECKPOINT_DIR)
	@echo "╭─ corpus benchmark  [$(TAG)] ─╮"
	uv run python evals/runners/policy_benchmark.py \
		--corpus $(CORPUS_DIR) \
		--output $(CHECKPOINT_DIR)/$(TAG)_policy.md \
		--json-output $(CHECKPOINT_DIR)/$(TAG)_policy.json
	@echo "╰─ saved → $(CHECKPOINT_DIR)/$(TAG)_policy.{md,json} ─╯"

# ── Dev tasks ──────────────────────────────────────────────────────────────
test: ## Run test suite
	uv run python -m pytest tests/ -x -q

lint: ## Run linters (ruff check + format)
	uv run ruff check . --fix
	uv run ruff format .

clean: ## Remove __pycache__ and .pytest_cache dirs
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true

# ── Docker ─────────────────────────────────────────────────────────────────
DOCKER_TAG   ?= latest
PORT         ?= 8081
BIND_ADDR    ?= 0.0.0.0
WORKERS      ?= 4

docker-build: ## Build Docker image locally
	@echo "🐳 Building Docker image..."
	docker build -t skill-scanner:$(DOCKER_TAG) .
	docker tag skill-scanner:$(DOCKER_TAG) skill-scanner:latest
	@echo "✅ Build complete: skill-scanner:$(DOCKER_TAG)"

docker-save: ## Export image to tar (for offline deploy)
	@echo "📦 Saving image to $(IMAGE_FILE)..."
	docker save skill-scanner:latest -o $(IMAGE_FILE)
	@ls -lh $(IMAGE_FILE)

docker-load: ## Load image from tar
	@echo "📦 Loading image from $(IMAGE_FILE)..."
	docker load -i $(IMAGE_FILE) > /dev/null 2>&1 || true
	@echo "✅ Image loaded"

docker-deploy: ## Deploy container (stop old → load image → start new)
	@echo "🚀 Deploying Skill Scanner..."
	@echo "   PORT=$(PORT)  BIND=$(BIND_ADDR)  WORKERS=$(WORKERS)"
	@if docker ps -a --format '{{.Names}}' | grep -q '^$(CONTAINER_NAME)$$'; then \
		echo "   Stopping old container..."; \
		docker stop $(CONTAINER_NAME) 2>/dev/null || true; \
		docker rm $(CONTAINER_NAME) 2>/dev/null || true; \
	fi
	@if [ -f $(IMAGE_FILE) ]; then \
		echo "   Loading image..."; \
		docker load -i $(IMAGE_FILE) > /dev/null 2>&1 || true; \
	fi
	docker run -d \
		--name $(CONTAINER_NAME) \
		--restart unless-stopped \
		-p $(BIND_ADDR):$(PORT):8000 \
		--env-file $(ENV_FILE) \
		--add-host=host.docker.internal:host-gateway \
		-e SKILL_SCANNER_WORKERS=$(WORKERS) \
		-e LOG_LEVEL=info \
		skill-scanner:$(DOCKER_TAG)
	@echo "   Waiting for service..."
	@sleep 8
	@curl -f -s http://localhost:$(PORT)/health > /dev/null \
		|| (echo "❌ Health check failed" && docker logs $(CONTAINER_NAME) && exit 1)
	@echo ""
	@echo "✅ Deployed successfully!"
	@echo "   Local:  http://localhost:$(PORT)"
	@echo "   Docs:   http://localhost:$(PORT)/docs"

docker-run: ## Run container in foreground (for testing)
	docker run --rm -p $(BIND_ADDR):$(PORT):8000 \
		--env-file $(ENV_FILE) \
		-e SKILL_SCANNER_WORKERS=$(WORKERS) \
		-e LOG_LEVEL=info \
		skill-scanner:$(DOCKER_TAG)

docker-stop: ## Stop and remove container
	@docker stop $(CONTAINER_NAME) 2>/dev/null || true
	@docker rm $(CONTAINER_NAME) 2>/dev/null || true
	@echo "✅ Container stopped"

docker-logs: ## Show container logs (follow)
	docker logs -f $(CONTAINER_NAME)

docker-shell: ## Open shell in running container
	docker exec -it $(CONTAINER_NAME) bash

docker-clean: ## Remove container and images
	-docker stop $(CONTAINER_NAME) 2>/dev/null || true
	-docker rm $(CONTAINER_NAME) 2>/dev/null || true
	-docker rmi skill-scanner:latest 2>/dev/null || true
	@echo "✅ Cleanup complete"

# ── Docker Compose ─────────────────────────────────────────────────────────
docker-compose-up: ## Start services with Docker Compose
	docker-compose up -d

docker-compose-down: ## Stop services with Docker Compose
	docker-compose down