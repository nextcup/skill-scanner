# Skill Scanner API 快速参考

## 基础信息

```
Base URL: http://localhost:8000
协议: HTTP/HTTPS
格式: JSON
```

## 端点速查

| 端点 | 方法 | 功能 |
|------|------|------|
| `/health` | GET | 健康检查 |
| `/analyzers` | GET | 列出分析器 |
| `/scan` | POST | 扫描单个技能 |
| `/scan-upload` | POST | 上传 ZIP 同步扫描 |
| `/scan-upload-async` | POST | 上传 ZIP 异步扫描 |
| `/scan-upload-async/{id}` | GET | 获取异步上传扫描结果 |
| `/scan-batch` | POST | 批量扫描 |
| `/scan-batch/{id}` | GET | 获取批量结果 |

## 扫描请求字段

### 必填字段

| 字段 | 类型 | 说明 |
|------|------|------|
| `skill_directory` | string | 技能包路径（`/scan`） |
| `skills_directory` | string | 批量扫描目录（`/scan-batch`） |
| `file` | binary | ZIP 文件（`/scan-upload`、`/scan-upload-async`） |

### 可选字段（扫描配置）

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `policy` | string | null | `strict`/`balanced`/`permissive` |
| `use_llm` | boolean | false | 启用 LLM 分析 |
| `llm_provider` | string | "anthropic" | LLM 提供商 |
| `use_behavioral` | boolean | false | 启用行为分析 |
| `use_virustotal` | boolean | false | 启用 VirusTotal |
| `vt_upload_files` | boolean | false | 上传到 VT |
| `use_aidefense` | boolean | false | 启用 AI Defense |
| `use_trigger` | boolean | false | 启用触发器分析 |
| `enable_meta` | boolean | false | 启用元分析 |
| `llm_consensus_runs` | int | 1 | LLM 共识轮次 |

### 批量扫描专用

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `recursive` | boolean | false | 递归子目录 |
| `check_overlap` | boolean | false | 重叠检测 |

## 扫描响应字段

| 字段 | 类型 | 说明 |
|------|------|------|
| `scan_id` | string | 扫描 ID |
| `skill_name` | string | 技能名称 |
| `is_safe` | boolean | 是否安全 |
| `max_severity` | string | 最高严重级别 |
| `findings_count` | int | 发现数量 |
| `scan_duration_seconds` | float | 耗时（秒） |
| `timestamp` | string | 时间戳 |
| `findings` | array | 发现列表 |
| `meta_analysis` | object\|null | 元分析结果（需 `enable_meta=true`） |

## 严重级别

```
critical > high > medium > low > info
```

## LLM 提供商

```
anthropic (默认) | openai | azure | bedrock | gemini
```

## 请求头（可选）

```
X-VirusTotal-Key: string
X-AIDefense-Key: string
```

## 快速命令

```bash
# 健康检查
curl http://localhost:8000/health

# 基础扫描
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"skill_directory": "/path/to/skill"}'

# 完整扫描
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{
    "skill_directory": "/path/to/skill",
    "policy": "strict",
    "use_llm": true,
    "use_behavioral": true,
    "enable_meta": true
  }'

# 同步上传扫描
curl -X POST http://localhost:8000/scan-upload \
  -F "file=@skill.zip"

# 异步上传扫描（推荐用于大文件/耗时分析）
curl -X POST http://localhost:8000/scan-upload-async \
  -F "file=@skill.zip" \
  -F "use_llm=true" \
  -F "enable_meta=true"

# 查询异步扫描结果
curl http://localhost:8000/scan-upload-async/<scan_id>

# 批量扫描
curl -X POST http://localhost:8000/scan-batch \
  -H "Content-Type: application/json" \
  -d '{"skills_directory": "/path/to/skills", "recursive": true}'
```

## 错误码

| 状态码 | 说明 |
|--------|------|
| 200 | 成功 |
| 400 | 参数错误 |
| 403 | 路径访问被拒绝 |
| 404 | 资源未找到 / Scan ID 过期 |
| 413 | 上传文件超限（50 MB） |
| 422 | 验证失败 |
| 500 | 服务器错误 |

## 响应示例

### 同步扫描响应
```json
{
  "scan_id": "scan_abc123",
  "skill_name": "my-skill",
  "is_safe": true,
  "max_severity": "low",
  "findings_count": 1,
  "scan_duration_seconds": 2.456,
  "timestamp": "2026-05-13T15:30:00Z",
  "findings": [...],
  "meta_analysis": null
}
```

### 异步扫描立即响应
```json
{
  "scan_id": "6b4f42a0-dbcb-4a3a-94b2-c30644e8d5d0",
  "status": "processing",
  "message": "scan-upload started. Use GET /scan-upload-async/{scan_id} to check status."
}
```

### 异步扫描完成响应
```json
{
  "scan_id": "6b4f42a0-...",
  "status": "completed",
  "started_at": "2026-05-18T10:30:00",
  "completed_at": "2026-05-18T10:30:15",
  "result": { "..." }
}
```

---

*完整文档：[docs/reference/api-endpoint-reference.md](reference/api-endpoint-reference.md)*