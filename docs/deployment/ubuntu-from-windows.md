# Windows Docker → Ubuntu 部署指南

本文档说明如何从 Windows Docker Desktop 构建的镜像部署到 Ubuntu 服务器。

## 架构说明

**为什么可以跨平台？**
- Windows Docker Desktop 使用 WSL2 后端，实际运行的是 Linux 容器
- 我们使用 `--platform linux/amd64` 构建，确保镜像架构兼容
- Docker 镜像格式是跨平台的，`docker save` 生成的 tar 文件可以在任何支持 Docker 的 Linux 系统上加载

**部署架构：**
```
Windows (Docker Desktop)          Ubuntu Server
─────────────────────            ──────────────
构建 Linux 镜像  ───tar 文件──→   加载并运行
platform: linux/amd64            docker load
docker save                      docker run
```

## 部署步骤

### 步骤 1: 在 Windows 上构建镜像

已在上一阶段完成，镜像位于：
```
D:\proj\PycharmProjects\skill-scanner\skill-scanner-linux-amd64.tar (245MB)
```

### 步骤 2: 传输文件到 Ubuntu

使用 SCP、SFTP 或其他方式传输以下文件到 Ubuntu 服务器：
- `skill-scanner-linux-amd64.tar` (镜像文件)
- `scripts/ubuntu-deploy.sh` (部署脚本)

**示例命令（在 Windows PowerShell 或 CMD 中）：**
```powershell
# 使用 SCP (需要 OpenSSH 客户端)
scp skill-scanner-linux-amd64.tar user@ubuntu-server:/home/user/
scp scripts/ubuntu-deploy.sh user@ubuntu-server:/home/user/

# 或使用 WinSCP、FileZilla 等图形化工具
```

### 步骤 3: 在 Ubuntu 上部署

SSH 连接到 Ubuntu 服务器：
```bash
ssh user@ubuntu-server
```

然后执行部署：
```bash
# 添加执行权限
chmod +x ubuntu-deploy.sh

# 运行部署脚本
./ubuntu-deploy.sh
```

**脚本会自动完成：**
1. 检查并安装 Docker（如果未安装）
2. 导入镜像 tar 文件
3. 停止旧容器（如果存在）
4. 启动新容器
5. 验证服务健康状态

## 手动部署（不使用脚本）

如果需要更精细的控制，可以手动执行：

```bash
# 1. 安装 Docker（如果未安装）
sudo apt-get update
sudo apt-get install -y docker.io
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker $USER

# 注销并重新登录以使 docker 组生效

# 2. 导入镜像
docker load -i skill-scanner-linux-amd64.tar

# 3. 验证镜像
docker images | grep skill-scanner

# 4. 运行容器
docker run -d \
    --name skill-scanner-api \
    --restart unless-stopped \
    -p 8000:8000 \
    -e SKILL_SCANNER_WORKERS=2 \
    -e LOG_LEVEL=info \
    skill-scanner:latest

# 5. 验证部署
curl http://localhost:8000/health
```

## 离线环境部署

对于完全离线的 Ubuntu 服务器：

### 准备阶段（联网环境）

1. **导出基础镜像**（可选，如果 Ubuntu 没有 Docker）：
```bash
# 在 Windows 上
docker pull python:3.12-slim
docker save python:3.12-slim -o python-3.12-slim.tar
```

2. **打包所有文件**：
```bash
mkdir skill-scanner-offline
cp skill-scanner-linux-amd64.tar skill-scanner-offline/
cp scripts/ubuntu-deploy.sh skill-scanner-offline/
# 如果需要，也包含基础镜像
cp python-3.12-slim.tar skill-scanner-offline/

# 打包
tar -czf skill-scanner-offline.tar.gz skill-scanner-offline/
```

3. **传输到离线服务器**（使用 U 盘、光盘等）

### 部署阶段（离线环境）

```bash
# 解压
tar -xzf skill-scanner-offline.tar.gz
cd skill-scanner-offline

# 如果需要，先加载基础镜像
docker load -i python-3.12-slim.tar

# 运行部署脚本
./ubuntu-deploy.sh
```

## 环境变量配置

### 基础配置

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `SKILL_SCANNER_WORKERS` | 2 | Gunicorn worker 数量 |
| `LOG_LEVEL` | info | 日志级别 (debug/info/warning/error) |

### LLM 配置（必需，用于 LLM 分析器）

| 变量 | 说明 |
|------|------|
| `SKILL_SCANNER_LLM_API_KEY` | Anthropic API Key |
| `SKILL_SCANNER_LLM_MODEL` | 模型名称 (默认: claude-3-5-sonnet-20241022) |

### 可选服务

| 变量 | 说明 |
|------|------|
| `VIRUSTOTAL_API_KEY` | VirusTotal API Key |
| `AI_DEFENSE_API_KEY` | Cisco AI Defense API Key |

**设置环境变量：**
```bash
# 方式 1: 在 docker run 命令中设置
docker run -d \
    -e SKILL_SCANNER_LLM_API_KEY=sk-ant-xxx \
    -e SKILL_SCANNER_WORKERS=4 \
    skill-scanner:latest

# 方式 2: 使用 .env 文件
cat > .env << EOF
SKILL_SCANNER_LLM_API_KEY=sk-ant-xxx
SKILL_SCANNER_WORKERS=4
LOG_LEVEL=info
EOF

docker run -d --env-file .env skill-scanner:latest

# 方式 3: 修改部署脚本
# 编辑 scripts/ubuntu-deploy.sh，修改 docker run 命令的环境变量部分
```

## 性能调优

### Worker 数量

根据服务器 CPU 核心数调整 worker 数量：

| CPU 核心 | 推荐 Workers | 计算公式 |
|----------|-------------|----------|
| 1 | 2 | `cores × 2` |
| 2 | 4 | `cores × 2` |
| 4 | 6-8 | `cores × 1.5 ~ 2` |
| 8+ | 12-16 | `cores × 1.5 ~ 2` |

**调整方法：**
```bash
# 停止容器
docker stop skill-scanner-api
docker rm skill-scanner-api

# 重新运行（调整 WORKERS）
export WORKERS=4
docker run -d \
    --name skill-scanner-api \
    -e SKILL_SCANNER_WORKERS=$WORKERS \
    skill-scanner:latest
```

### 内存限制

如果服务器内存有限，可以限制容器内存使用：

```bash
docker run -d \
    --name skill-scanner-api \
    --memory="1g" \
    --memory-swap="2g" \
    skill-scanner:latest
```

### CPU 限制

限制容器使用的 CPU 核心数：

```bash
docker run -d \
    --name skill-scanner-api \
    --cpus="1.5" \
    skill-scanner:latest
```

## 验证和测试

### 健康检查

```bash
# 基础健康检查
curl http://localhost:8000/health

# 查看详细状态
curl http://localhost:8000/health | jq .

# 检查分析器列表
curl http://localhost:8000/analyzers | jq .
```

### 端点测试

```bash
# API 文档（浏览器访问）
open http://localhost:8000/docs

# 测试扫描端点（需要有效路径）
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"skill_path": "/path/to/skill"}'
```

### 性能测试

```bash
# 使用 ab (Apache Bench)
ab -n 1000 -c 10 http://localhost:8000/health

# 使用 wrk
wrk -t4 -c100 -d30s http://localhost:8000/health
```

## 故障排查

### 容器无法启动

```bash
# 查看容器日志
docker logs skill-scanner-api

# 查看最近的日志
docker logs --tail 50 skill-scanner-api

# 实时查看日志
docker logs -f skill-scanner-api
```

### 端口冲突

如果 8000 端口已被占用：

```bash
# 使用其他端口
docker run -d \
    --name skill-scanner-api \
    -p 8080:8000 \
    skill-scanner:latest

# 然后访问 http://localhost:8080
```

### 健康检查失败

```bash
# 检查容器是否运行
docker ps

# 进入容器手动检查
docker exec -it skill-scanner-api bash

# 在容器内测试
python -c "import httpx; httpx.get('http://localhost:8000/health').raise_for_status()"
```

### 镜像导入失败

```bash
# 验证 tar 文件完整性
md5sum skill-scanner-linux-amd64.tar

# 重新传输（使用二进制模式）
# 如果使用 SCP，添加 -B 标志
scp -B skill-scanner-linux-amd64.tar user@server:~/
```

## 更新和维护

### 更新镜像

当有新版本时：

```bash
# 在 Windows 上构建新版本
docker build --platform linux/amd64 -t skill-scanner:v2.0.0 .

# 导出新版本
docker save skill-scanner:v2.0.0 -o skill-scanner-v2.0.0.tar

# 传输到 Ubuntu
scp skill-scanner-v2.0.0.tar user@server:~/

# 在 Ubuntu 上更新
ssh user@server

# 加载新镜像
docker load -i skill-scanner-v2.0.0.tar

# 停止并删除旧容器
docker stop skill-scanner-api
docker rm skill-scanner-api

# 启动新版本
docker run -d --name skill-scanner-api -p 8000:8000 skill-scanner:v2.0.0
```

### 备份和恢复

```bash
# 导出当前容器配置
docker inspect skill-scanner-api > container-config.json

# 备份数据卷（如果有）
docker run --rm --volumes-from skill-scanner-api \
    -v $(pwd):/backup \
    ubuntu tar cvf /backup/skill-scanner-data.tar /app/.cache

# 恢复数据卷
docker run --rm --volumes-from skill-scanner-api \
    -v $(pwd):/backup \
    ubuntu tar xvf /backup/skill-scanner-data.tar -C /
```

## 生产环境建议

1. **使用反向代理** (Nginx/Caddy)
   - SSL/TLS 终止
   - 静态文件服务
   - 请求限流

2. **配置日志轮转**
   ```bash
   # 配置 Docker 日志驱动
   docker run -d \
       --log-driver json-file \
       --log-opt max-size=10m \
       --log-opt max-file=3 \
       skill-scanner:latest
   ```

3. **监控和告警**
   - 容器健康检查
   - 日志监控 (ELK/Loki)
   - 指标收集 (Prometheus)

4. **安全加固**
   - 使用非 root 用户运行（已配置）
   - 限制容器资源
   - 定期更新基础镜像

## 总结

✅ **已完成：**
- 在 Windows Docker Desktop 上构建 Linux 镜像
- 本地验证成功
- 导出为 tar 文件 (245MB)
- 创建 Ubuntu 部署脚本

✅ **下一步：**
1. 传输文件到 Ubuntu 服务器
2. 运行 `ubuntu-deploy.sh` 脚本
3. 验证部署：`curl http://ubuntu-server:8000/health`

**文件清单：**
```
skill-scanner/
├── skill-scanner-linux-amd64.tar      # Docker 镜像 (245MB)
└── scripts/
    └── ubuntu-deploy.sh                # 自动化部署脚本
```

**快速命令：**
```bash
# 传输
scp skill-scanner-linux-amd64.tar ubuntu-deploy.sh user@server:~/

# 部署
ssh user@server
chmod +x ubuntu-deploy.sh
./ubuntu-deploy.sh

# 验证
curl http://server-ip:8000/health
```
