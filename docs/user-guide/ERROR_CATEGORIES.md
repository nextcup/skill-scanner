# API 错误类别参考

本文档列出了 Skill Scanner API 返回的所有错误类别及其含义。

## 重要说明

**API 默认使用 `lenient` 模式**：这意味着即使 SKILL.md 缺少 `name` 或 `description` 字段，扫描也会继续执行，系统会使用默认值填充缺失字段。

如果需要严格模式（缺少字段时报错），可以在 CLI 中使用 `--strict` 选项。


## 错误响应格式

### 同步端点 (`/scan`, `/scan-upload`)

```json
{
  "detail": "SKILL_MD_FORMAT_ERROR: SKILL.md 缺少必需的 description 字段"
}
```

### 异步端点 (`/scan-upload-async`, `/scan-batch`)

```json
{
  "scan_id": "uuid",
  "status": "error",
  "started_at": "2026-05-19T12:00:00",
  "error_category": "SKILL_MD_FORMAT_ERROR",
  "error_reason": "SKILL.md 缺少必需的 description 字段",
  "error": "原始错误信息（兼容旧客户端）"
}
```

启用 `DEBUG=true` 时，还会包含 `stack_trace` 字段。

## 错误类别列表

### SKILL_MD_FORMAT_ERROR

**描述**: SKILL.md 文件格式错误

**可能原因**:
- 缺少必需的 `name` 字段
- 缺少必需的 `description` 字段
- YAML frontmatter 解析失败

**HTTP 状态码**: 400

**示例**:
```
SKILL_MD_FORMAT_ERROR: SKILL.md 缺少必需的 description 字段
SKILL_MD_FORMAT_ERROR: YAML frontmatter 解析失败: 'mapping values are not allowed here'
```

**解决方案**: 检查 SKILL.md 文件，确保包含 YAML frontmatter 且格式正确

---

### SKILL_MD_NOT_FOUND

**描述**: SKILL.md 文件不存在

**HTTP 状态码**: 400

**示例**:
```
SKILL_MD_NOT_FOUND: SKILL.md 文件不存在
SKILL_MD_NOT_FOUND: 没有找到 SKILL.md 或任何 .md 文件（lenient 模式）
```

**解决方案**: 确保上传的 ZIP 包中包含 SKILL.md 文件

---

### FILE_ENCODING_ERROR

**描述**: 文件编码错误

**可能原因**:
- 文件不是 UTF-8 编码
- 文件包含 NUL 字节（二进制文件）

**HTTP 状态码**: 400

**示例**:
```
FILE_ENCODING_ERROR: 文件编码错误，需要 UTF-8 格式
FILE_ENCODING_ERROR: 文件包含空字节，可能为二进制文件
```

**解决方案**: 确保所有文本文件使用 UTF-8 编码

---

### FILE_SIZE_ERROR

**描述**: 文件大小超过限制

**HTTP 状态码**: 400

**示例**:
```
FILE_SIZE_ERROR: 文件大小超过限制: 超过 10MB 限制
```

**解决方案**: 减小文件大小或联系管理员调整限制

---

### FILE_TYPE_ERROR

**描述**: 不支持的文件类型

**HTTP 状态码**: 400

**示例**:
```
FILE_TYPE_ERROR: 不支持的二进制文件类型
```

**解决方案**: 将二进制文件替换为源代码

---

### POLICY_CONFIG_ERROR

**描述**: 策略配置错误

**可能原因**:
- 策略名称未知
- 策略路径不是文件
- 策略文件扩展名错误

**HTTP 状态码**: 400

**示例**:
```
POLICY_CONFIG_ERROR: 未知的策略名称: unknown_policy
POLICY_CONFIG_ERROR: 策略路径不是文件
POLICY_CONFIG_ERROR: 策略文件必须是 .yaml 或 .yml 格式
```

**解决方案**: 检查策略名称或路径是否正确

---

### POLICY_PARSE_ERROR

**描述**: 策略 YAML 解析失败

**HTTP 状态码**: 400

**示例**:
```
POLICY_PARSE_ERROR: 策略 YAML 解析失败: mapping values are not allowed here
```

**解决方案**: 检查策略 YAML 语法是否正确

---

### POLICY_ERROR

**描述**: 其他策略相关错误

**HTTP 状态码**: 500

---

### YARA_RULE_ERROR

**描述**: YARA 规则错误

**HTTP 状态码**: 400

**示例**:
```
YARA_RULE_ERROR: YARA 规则错误: syntax error in rule 'malicious_code'
```

**解决方案**: 检查 YARA 规则语法

---

### CUSTOM_RULES_ERROR

**描述**: 自定义规则错误

**HTTP 状态码**: 400

---

### LLM_AUTH_ERROR

**描述**: LLM API 认证失败

**HTTP 状态码**: 500

**示例**:
```
LLM_AUTH_ERROR: LLM API 认证失败，请检查 API key 配置
```

**解决方案**: 检查 `SKILL_SCANNER_LLM_API_KEY` 环境变量

---

### LLM_TIMEOUT_ERROR

**描述**: LLM API 请求超时

**HTTP 状态码**: 500

**示例**:
```
LLM_TIMEOUT_ERROR: LLM API 请求超时
```

**解决方案**: 稍后重试或检查网络连接

---

### LLM_RATE_LIMIT_ERROR

**描述**: LLM API 配额用尽或触发速率限制

**HTTP 状态码**: 500

**示例**:
```
LLM_RATE_LIMIT_ERROR: LLM API 配额用尽或触发速率限制
```

**解决方案**: 等待一段时间后重试，或升级 API 配额

---

### LLM_NETWORK_ERROR

**描述**: LLM API 网络连接失败

**HTTP 状态码**: 500

**示例**:
```
LLM_NETWORK_ERROR: LLM API 网络连接失败
```

**解决方案**: 检查网络连接和代理设置

---

### LLM_ERROR

**描述**: 其他 LLM 相关错误

**HTTP 状态码**: 500

---

### AIDEFENSE_CONFIG_ERROR

**描述**: AI Defense 配置错误

**HTTP 状态码**: 500

**示例**:
```
AIDEFENSE_CONFIG_ERROR: AI Defense API URL 配置错误
```

**解决方案**: 检查 `aidefense_api_url` 参数

---

### AIDEFENSE_AUTH_ERROR

**描述**: AI Defense 认证失败

**HTTP 状态码**: 500

**示例**:
```
AIDEFENSE_AUTH_ERROR: AI Defense 认证失败
```

**解决方案**: 检查 API key 配置

---

### AIDEFENSE_TIMEOUT_ERROR

**描述**: AI Defense 请求超时

**HTTP 状态码**: 500

---

### AIDEFENSE_ERROR

**描述**: 其他 AI Defense 相关错误

**HTTP 状态码**: 500

---

### VIRUSTOTAL_AUTH_ERROR

**描述**: VirusTotal API key 无效

**HTTP 状态码**: 500

**解决方案**: 检查 `X-VirusTotal-Key` 请求头

---

### VIRUSTOTAL_NETWORK_ERROR

**描述**: VirusTotal 网络连接失败

**HTTP 状态码**: 500

---

### VIRUSTOTAL_ERROR

**描述**: 其他 VirusTotal 相关错误

**HTTP 状态码**: 500

---

### FILE_NOT_FOUND

**描述**: 文件或目录不存在

**HTTP 状态码**: 400

---

### PERMISSION_ERROR

**描述**: 文件系统权限不足

**HTTP 状态码**: 400

---

### FILESYSTEM_ERROR

**描述**: 其他文件系统错误

**HTTP 状态码**: 400

---

### SKILL_LOAD_ERROR

**描述**: Skill 加载失败（其他原因）

**HTTP 状态码**: 500

---

### UNKNOWN_ERROR

**描述**: 未知错误

**HTTP 状态码**: 500

**注意**: 如果遇到此错误，请检查服务器日志获取详细信息

---

### META_ANALYSIS_FAILED

**描述**: Meta 分析失败（非致命错误）

**说明**: Meta 分析失败不会导致扫描失败，但 `meta_analysis` 字段会返回 `null`。这可能发生在 SKILL.md 格式不正确时。

**HTTP 状态码**: 200（扫描继续进行）

**示例**:
```
Meta-analysis failed: Failed to parse YAML frontmatter: mapping values are not allowed in this context
```

**解决方案**: 修复 SKILL.md 的 YAML frontmatter 格式

---

## meta_analysis 为 null 的常见原因

当 `enable_meta=true` 时，如果 `meta_analysis` 返回 `null`，通常是以下原因：

| 原因 | 日志信息 | 解决方案 |
|------|----------|----------|
| SKILL.md YAML 格式错误 | `Failed to parse YAML frontmatter` | 修复 YAML 语法 |
| LLM API 未配置 | `API key: MISSING` | 设置 `SKILL_SCANNER_LLM_API_KEY` |
| 没有发现 findings | （无日志） | 无需 meta 分析 |
| Meta 分析器超时 | `Meta-analysis failed: timeout` | 检查网络连接 |
| LLM API 速率限制 | `rate limit` | 稍后重试 |

**注意**: API 默认使用 `lenient` 模式，即使 SKILL.md 格式有问题，主扫描也会成功进行。

## 调试模式

设置环境变量 `DEBUG=true` 可以在错误响应中获取完整的堆栈跟踪：

```bash
export DEBUG=true
mcp-scanner-api --host 0.0.0.0 --port 8080
```

或者在 Windows PowerShell 中：

```powershell
$env:DEBUG = "true"
mcp-scanner-api --host 0.0.0.0 --port 8080
```

## HTTP 状态码说明

| 状态码 | 含义 | 典型场景 |
|--------|------|----------|
| 400 | Bad Request | 客户端请求参数错误（如文件格式不正确） |
| 403 | Forbidden | 访问被拒绝（路径不在允许列表中） |
| 404 | Not Found | 资源不存在（如 scan_id 过期） |
| 413 | Payload Too Large | 上传文件超过大小限制 |
| 500 | Internal Server Error | 服务器内部错误（如 LLM API 失败） |

## 日志查看

服务器端日志会记录完整的错误信息和堆栈跟踪：

```bash
# 默认日志输出到控制台
# 如果配置了日志文件，可以查看：
tail -f /var/log/skill-scanner/api.log
```

日志格式示例：

```
2026-05-19 12:00:00 ERROR skill_scanner.api Scan failed: SKILL_MD_FORMAT_ERROR - SKILL.md 缺少必需的 description 字段
Traceback (most recent call last):
  File "...", line 468, in scan_skill
    result = scanner.scan_skill(skill_dir)
  ...
```
