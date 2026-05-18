# Docker 环境变量配置指南

## .env 文件位置

### 推荐位置

```
skill-scanner/
├── .env                    # 环境变量文件（与 docker-compose.yml 同目录）
├── .env.example           # 配置模板
├── docker-compose.yml
├── Dockerfile
└── skill_scanner/
```

### 读取规则

| 场景 | .env 位置 | 命令 |
|------|-----------|------|
| 默认 | 与 `docker-compose.yml` 同目录 | `docker-compose up -d` |
| 自定义路径 | 任何位置 | `docker-compose --env-file /path/to/.env up -d` |
| 多个文件 | 多个位置 | `docker-compose --env-file .env.base --env-file .env.local up -d` |

---

## 本地 LLM 配置（Docker 重要）

### 问题

在 Docker 容器中，`127.0.0.1` 和 `localhost` 指向容器本身，无法访问宿主机的本地 LLM 服务。

### 解决方案

使用 `host.docker.internal` 代替 `127.0.0.1` 或 `localhost`：

```bash
# ❌ 错误：容器内无法访问
SKILL_SCANNER_LLM_BASE_URL=http://127.0.0.1:9990/v1
SKILL_SCANNER_LLM_BASE_URL=http://localhost:9990/v1

# ✅ 正确：Docker Desktop 自动解析为宿主机 IP
SKILL_SCANNER_LLM_BASE_URL=http://host.docker.internal:9990/v1
```

### 各平台支持情况

| 平台 | `host.docker.internal` | 替代方案 |
|------|------------------------|----------|
| **Docker Desktop (Win/Mac)** | ✅ 支持 | - |
| **Docker Desktop Linux** | ✅ 支持 (v18.03+) | - |
| **原生 Docker Linux** | ❌ 不支持 | 使用 `172.17.0.1`（网关 IP） |

### Linux 原生 Docker 配置

```bash
# 方式 1：使用 host 网络模式（不推荐，会失去隔离）
docker run --network host ...

# 方式 2：使用网关 IP
docker run --add-host=host.docker.internal:172.17.0.1 ...

# 方式 3：在 docker-compose.yml 中配置
extra_hosts:
  - "host.docker.internal:172.17.0.1"
```

---

## 当前项目的 .env 配置

### 本地 LLM 配置（你的当前设置）

```bash
# .env 文件内容（已配置）
SKILL_SCANNER_LLM_API_KEY=EMPTY
SKILL_SCANNER_LLM_MODEL=openai/Qwen
SKILL_SCANNER_LLM_BASE_URL=http://127.0.0.1:9990/v1  # ⚠️ 需要修改
SKILL_SCANNER_LLM_API_VERSION=

# 威胁情报源（可选）
VIRUSTOTAL_API_KEY=7c47d...  # 已配置
THREATBOOK_API_KEY=ef5f8...   # 已配置
OTX_API_KEY=65930...          # 已配置
ZFTIP_URL=http://20.20.136.105:50000
ZFTIP_API_KEY=zhongfu-ti-...
```

### 修改为 Docker 兼容

```bash
# 将 127.0.0.1 替换为 host.docker.internal
SKILL_SCANNER_LLM_BASE_URL=http://host.docker.internal:9990/v1
```

---

## 环境变量优先级

Docker Compose 中的环境变量优先级（从高到低）：

1. **docker-compose.yml** 中的 `environment` 字段
2. **shell 环境变量** (运行 `docker-compose` 时)
3. **.env 文件** (通过 `env_file` 指定)
4. **系统默认值**

### 示例

```yaml
# docker-compose.yml
services:
  skill-scanner-api:
    env_file:
      - .env                    # 优先级 3
    environment:
      - WORKERS=4                # 优先级 1（覆盖 .env 中的设置）
      - LOG_LEVEL=debug          # 优先级 1
```

```bash
# 命令行环境变量（优先级 2，覆盖 .env 和 docker-compose.yml）
WORKERS=8 docker-compose up -d
```

---

## 生产环境部署建议

### 方式 1：使用 .env（推荐）

```bash
# 1. 复制模板
cp .env.example .env

# 2. 编辑配置
vim .env

# 3. 启动服务
docker-compose up -d
```

### 方式 2：使用 secrets（更安全）

```yaml
# docker-compose.yml
services:
  skill-scanner-api:
    secrets:
      - llm_api_key
    environment:
      - SKILL_SCANNER_LLM_API_KEY_FILE=/run/secrets/llm_api_key

secrets:
  llm_api_key:
    file: ./secrets/llm_api_key.txt
```

### 方式 3：使用 orchestrator secrets

**Kubernetes:**
```yaml
env:
  - name: SKILL_SCANNER_LLM_API_KEY
    valueFrom:
      secretKeyRef:
        name: skill-scanner-secrets
        key: api-key
```

**Docker Swarm:**
```bash
echo "your_api_key" | docker secret create llm_api_key -
docker service create \
  --secret llm_api_key \
  skill-scanner-api
```

---

## 常见问题

### Q1: .env 文件修改后需要重启容器吗？

**A:** 是的，需要重启才能生效：

```bash
docker-compose down
docker-compose up -d
```

### Q2: 如何验证环境变量是否生效？

```bash
# 查看容器环境变量
docker exec skill-scanner-api env | grep LLM

# 查看特定变量
docker exec skill-scanner-api printenv SKILL_SCANNER_LLM_BASE_URL
```

### Q3: 敏感信息如何安全存储？

**推荐方案：**

| 方案 | 适用场景 |
|------|----------|
| `.env` + `.gitignore` | 本地开发 |
| 环境变量注入 | CI/CD |
| Secrets 管理 | 生产环境 |
| 密钥管理服务 | 企业环境 |

### Q4: Docker Desktop 中 `host.docker.internal` 无法解析？

**解决方案：**

```bash
# 1. 确保 Docker Desktop 正在运行
# 2. 检查 DNS 设置
docker run --rm alpine ping -c 1 host.docker.internal

# 3. 如果还是失败，重启 Docker Desktop
```

### Q5: WSL2 中如何配置本地 LLM？

```bash
# WSL2 中可以直接使用宿主机 IP
# 方法 1：查找宿主机 IP
cat /etc/resolv.conf | grep nameserver | awk '{print $2}'

# 方法 2：使用 .env 配置
SKILL_SCANNER_LLM_BASE_URL=http://$(cat /etc/resolv.conf | grep nameserver | awk '{print $2}'):9990/v1
```

---

## 快速参考

### 当前配置的 LLM API

```bash
# 容器内配置（需要修改 .env）
Base URL: http://host.docker.internal:9990/v1
Model: openai/Qwen
API Key: EMPTY
```

### 验证配置

```bash
# 在 WSL 中测试
cd ~/skill-scanner-deploy
./ubuntu-deploy.sh

# 验证环境变量
docker exec skill-scanner-api env | grep -E "LLM|API"

# 测试健康检查
curl http://localhost:8000/health
```

---

*更新时间：2026-05-13*
