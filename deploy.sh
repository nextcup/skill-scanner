#!/bin/bash
# 简化的 Skill Scanner 部署脚本
# 使用方法：./deploy.sh [端口] [绑定地址]

set -e

IMAGE_FILE="skill-scanner-linux-amd64.tar"
CONTAINER_NAME="skill-scanner-api"
ENV_FILE=".env"
WORKERS=2

# 默认参数
PORT=${1:-8081}
BIND_ADDR=${2:-0.0.0.0}

# 颜色输出
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

# 显示配置信息
echo "🚀 Skill Scanner 部署"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "端口: $PORT"
echo "绑定: $BIND_ADDR"
echo "Workers: $WORKERS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# 停止旧容器
if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
  log_info "停止旧容器..."
  docker stop "$CONTAINER_NAME" 2>/dev/null || true
  docker rm "$CONTAINER_NAME" 2>/dev/null || true
fi

# 加载镜像
if [ ! -f "$IMAGE_FILE" ]; then
  log_error "镜像文件不存在: $IMAGE_FILE"
  exit 1
fi

log_info "加载镜像..."
docker load -i "$IMAGE_FILE" > /dev/null 2>&1 || true

# 启动容器
log_info "启动容器..."
docker run -d \
  --name "$CONTAINER_NAME" \
  --restart unless-stopped \
  -p "${BIND_ADDR}:${PORT}:8000" \
  --env-file "$ENV_FILE" \
  --add-host=host.docker.internal:host-gateway \
  -e SKILL_SCANNER_WORKERS=$WORKERS \
  -e LOG_LEVEL=info \
  skill-scanner:latest

# 等待启动
sleep 8

# 健康检查
if curl -f -s "http://localhost:$PORT/health" > /dev/null; then
  echo ""
  echo "✅ 部署成功！"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  if [ "$BIND_ADDR" = "0.0.0.0" ] || [ "$BIND_ADDR" = "127.0.0.1" ]; then
    echo "📍 本地访问:   http://localhost:$PORT"
  fi
  echo "📍 网络访问:   http://192.168.1.137:$PORT"
  echo "📍 API 文档:    http://192.168.1.137:$PORT/docs"
  echo ""
  echo "常用命令:"
  echo "  查看日志: docker logs -f $CONTAINER_NAME"
  echo "  停止服务: docker stop $CONTAINER_NAME"
  echo "  重启服务: docker restart $CONTAINER_NAME"
  echo "  进入容器: docker exec -it $CONTAINER_NAME bash"
else
  log_error "健康检查失败！"
  docker logs "$CONTAINER_NAME" | tail -20
  exit 1
fi
