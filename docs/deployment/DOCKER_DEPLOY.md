# Docker 部署完成！

## ✅ 已完成的工作

### 1. 本地构建和验证
- ✅ 在 Windows Docker Desktop 上构建 Linux AMD64 镜像
- ✅ 本地运行测试成功
- ✅ 验证所有 API 端点正常

### 2. 文件创建
- ✅ `Dockerfile` - 多阶段构建配置
- ✅ `docker-compose.yml` - Docker Compose 编排
- ✅ `gunicorn.conf.py` - Gunicorn 生产配置
- ✅ `skill-scanner-linux-amd64.tar` (245MB) - 可部署的镜像
- ✅ `scripts/ubuntu-deploy.sh` - Ubuntu 自动部署脚本
- ✅ `docs/deployment/ubuntu-from-windows.md` - 完整部署文档

## 📦 部署文件

位置：`D:\proj\PycharmProjects\skill-scanner\`

| 文件 | 大小 | 说明 |
|------|------|------|
| `skill-scanner-linux-amd64.tar` | 245MB | Docker 镜像（可直接部署到 Ubuntu） |
| `scripts/ubuntu-deploy.sh` | 4KB | 自动化部署脚本 |

## 🚀 快速部署到 Ubuntu

### 使用 Makefile（推荐）

项目提供了 Makefile 简化构建和部署流程：

```bash
# 在 WSL Ubuntu 中执行
cd /mnt/d/proj/PycharmProjects/skill-scanner/

# 构建镜像
make docker-build

# 导出为 tar（用于离线部署）
make docker-save

# 部署容器（默认 8081 端口）
make docker-deploy

# 指定端口部署
make docker-deploy PORT=9090

# 指定 worker 数量
make docker-deploy WORKERS=8
```

**Makefile 命令速查：**

| 命令 | 功能 |
|------|------|
| `make docker-build` | 构建镜像 `skill-scanner:latest` |
| `make docker-save` | 导出为 `skill-scanner-linux-amd64.tar` |
| `make docker-load` | 从 tar 加载镜像 |
| `make docker-deploy` | 部署容器（默认 8081 端口） |
| `make docker-run` | 前台运行（测试用） |
| `make docker-stop` | 停止容器 |

### 使用 WSL 构建部署

在 Windows 上使用 WSL Ubuntu 构建：

```bash
# 进入 WSL Ubuntu
wsl -d Ubuntu

# 进入项目目录（注意 Windows 路径转换）
cd /mnt/d/proj/PycharmProjects/skill-scanner/

# 如果 WSL 网络不可用，先重启 WSL
wsl --shutdown
# 等待几秒后重新进入
wsl -d Ubuntu

# 使用 Makefile 构建
make docker-build
make docker-save
```

### 手动部署步骤

#### 步骤 1: 传输文件到 Ubuntu

```powershell
# 在 Windows PowerShell 或 CMD 中执行
scp skill-scanner-linux-amd64.tar scripts/ubuntu-deploy.sh user@ubuntu-server:/home/user/
```

#### 步骤 2: SSH 到 Ubuntu 并部署

```bash
# 连接到 Ubuntu
ssh user@ubuntu-server

# 运行部署脚本
cd ~
chmod +x ubuntu-deploy.sh
./ubuntu-deploy.sh
```

**脚本会自动：**
1. 安装 Docker（如果未安装）
2. 导入镜像
3. 启动容器
4. 验证服务健康

### 步骤 3: 验证部署

```bash
# 健康检查
curl http://localhost:8000/health

# 浏览器访问 API 文档
# http://your-ubuntu-ip:8000/docs
```

## 🔧 配置选项

### 环境变量

```bash
# 基础配置
export WORKERS=2              # Gunicorn worker 数量
export LOG_LEVEL=info         # 日志级别

# LLM 配置（必需）
export LLM_API_KEY=sk-ant-xxx # Anthropic API Key
export LLM_MODEL=claude-3-5-sonnet-20241022

# 可选服务
export VIRUSTOTAL_API_KEY=xxx
export AI_DEFENSE_API_KEY=xxx
```

### Worker 数量调优

| CPU 核心 | 推荐 Workers |
|----------|-------------|
| 1 | 2 |
| 2 | 4 |
| 4 | 6-8 |
| 8+ | 12-16 |

## 📊 验证结果

### 本地测试通过

```json
{
  "status": "healthy",
  "version": "2.0.9.dev16+ga88ac2aec.d20260413",
  "analyzers_available": [
    "static_analyzer",
    "bytecode_analyzer",
    "pipeline_analyzer",
    "behavioral_analyzer",
    "llm_analyzer",
    "virustotal_analyzer",
    "aidefense_analyzer",
    "trigger_analyzer",
    "meta_analyzer"
  ]
}
```

### 服务端点

| 端点 | 说明 |
|------|------|
| `GET /health` | 健康检查 |
| `GET /docs` | Swagger API 文档 |
| `GET /analyzers` | 列出可用分析器 |
| `POST /scan` | 扫描单个技能 |
| `POST /scan-upload` | 上传并扫描 ZIP |
| `POST /scan-batch` | 批量扫描 |

## 📝 容器管理命令

```bash
# 查看日志
docker logs -f skill-scanner-api

# 停止服务
docker stop skill-scanner-api

# 重启服务
docker restart skill-scanner-api

# 进入容器
docker exec -it skill-scanner-api bash

# 查看资源使用
docker stats skill-scanner-api
```

## ⚠️ 常见问题

### CRLF 行尾问题

在 Linux 上执行脚本时出现 `/bin/bash^M` 错误：

```bash
# 错误信息
./deploy.sh: /bin/bash^M: No such file or directory

# 原因：文件包含 Windows 行尾符（CRLF \r\n）
# Linux 期望 LF (\n) 行尾

# 解决方案 1：使用 dos2unix（推荐）
yum install -y dos2unix  # RHEL/CentOS
apt install -y dos2unix   # Debian/Ubuntu
dos2unix deploy.sh

# 解决方案 2：使用 sed
sed -i 's/\r$//' deploy.sh

# 解决方案 3：使用 tr
tr -d '\r' < deploy.sh > deploy-fixed.sh
mv deploy-fixed.sh deploy.sh
chmod +x deploy.sh

# 批量转换所有 .sh 文件
find . -name "*.sh" -exec dos2unix {} \;
```

**预防方法：**
```bash
# Git 配置自动转换
git config --global core.autocrlf input

# VS Code 设置
# .vscode/settings.json
{
  "files.eol": "\n"
}

# 编辑器右下角选择 "LF" 而不是 "CRLF"
```

### WSL 网络问题

如果在 WSL Ubuntu 中网络不可用：

```bash
# 诊断
ip a  # 只有 lo 接口，没有 eth0

# 解决方案
wsl --shutdown
# 等待几秒后重新进入
wsl -d Ubuntu
```

## 🌐 离线环境部署

对于完全离线的 Ubuntu 服务器：

1. **准备阶段**（联网的 Windows）：
   ```bash
   # 镜像已在：skill-scanner-linux-amd64.tar
   ```

2. **传输到离线服务器**（U 盘、光盘等）

3. **部署**（离线 Ubuntu）：
   ```bash
   # 如果没有 Docker，需要先手动安装
   sudo apt-get install -y docker.io
   sudo systemctl start docker

   # 运行部署脚本
   ./ubuntu-deploy.sh
   ```

## 📖 详细文档

完整部署指南：[docs/deployment/ubuntu-from-windows.md](ubuntu-from-windows.md)

包含：
- 详细部署步骤
- 故障排查
- 性能调优
- 安全加固
- 更新和维护

## ✨ 特性

- ✅ **多进程架构**：Gunicorn + Uvicorn Workers
- ✅ **自动重启**：容器崩溃自动恢复
- ✅ **健康检查**：自动监控服务状态
- ✅ **资源限制**：可配置内存和 CPU 限制
- ✅ **日志管理**：完整的访问和错误日志
- ✅ **跨平台**：从 Windows 构建，部署到 Linux
- ✅ **离线支持**：可在无网络环境部署

## 🎯 下一步

1. **传输文件到 Ubuntu 服务器**
2. **运行 `ubuntu-deploy.sh`**
3. **访问 `http://your-server:8000/docs` 查看 API 文档**
4. **配置 LLM API Key 以启用完整功能**

---

**构建信息：**
- 平台：linux/amd64
- 镜像大小：256MB (压缩后 245MB)
- Python 版本：3.12
- Gunicorn 版本：23.0.0
- Uvicorn 版本：0.40.0

**验证状态：** ✅ 本地测试通过，可直接部署到生产环境
