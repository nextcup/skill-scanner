---
name: skill-security-scan
description: 使用 skill-scanner 扫描 AI Agent Skills 的安全威胁。当用户想检查 skill 是否安全、扫描 skill 目录/zip/URL 的漏洞、检测 skill 中的 prompt injection 或数据泄露、或询问任何关于 skill 安全分析的问题时，使用此 skill。触发短语包括"检查这个skill是否安全"、"扫描skill"、"这个skill安全吗"、"skill安全检查"、"帮我看看skill有没有问题"，或用户提供 skill 路径/zip/URL 并询问其安全性时。也适用于用户提到"skill安全"、"skill扫描"、"skill检测"等场景。
---

# Skill 安全扫描

使用 skill-scanner 对 AI Agent Skill 执行完整的安全扫描。

## 适用场景

用户提供了一个 skill 的位置——本地目录路径、`.zip` 文件路径、或指向 `.zip` 文件的 URL——想要知道它是否安全。你的任务是运行扫描、等待结果，并以清晰的方式呈现发现。

## 前置准备

### 确定 scripts 目录路径

本 skill 的所有命令都必须在 `scripts` 子目录下执行。首先确定路径：

```bash
SKILL_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "$0")")/scripts"
# Windows 下使用:
# SKILL_DIR=%USERPROFILE%\.claude\skills\skill-security-scan\scripts
```

## 文件扫描命令

所有命令使用 `uv --directory <SCRIPTS_DIR>` 指定工作目录，无需手动 cd。

其中 `<INPUT>` 是用户提供的路径或 URL。

### [默认]文件扫描命令

```bash
uv --directory "$SKILL_DIR" run --index-url https://pypi.tuna.tsinghua.edu.cn/simple python -m skill_scanner.cli.cli scan-all <INPUT> \
  --use-behavioral \
  --use-llm \
  --format csv \
  --output scan_result-<timestamp>.csv \
  --recursive \
  --lenient \
  --enable-meta
```

### 单个文件扫描命令

```bash
uv --directory "$SKILL_DIR" run --index-url https://pypi.tuna.tsinghua.edu.cn/simple python -m skill_scanner.cli.cli scan <INPUT> \
  --use-behavioral \
  --use-llm \
  --format csv \
  --output scan_result-<timestamp>.csv \
  --lenient \
  --enable-meta
```

### 模式匹配扫描命令

```bash
uv --directory "$SKILL_DIR" run --index-url https://pypi.tuna.tsinghua.edu.cn/simple python -m skill_scanner.cli.cli scan <INPUT> \
  --use-behavioral \
  --format csv \
  --output scan_result-<timestamp>.csv \
  --lenient \
```



## 工作流程

### 1. 确定输入

从用户的消息中提取 skill 位置，支持三种格式：

- 本地目录（如 `./my-skill`、`D:\skills\agent-skill`）
- 本地 zip 文件（如 `./skill.zip`、`C:\Downloads\skill.zip`）
- zip 文件的 URL（如 `https://example.com/skill.zip`）

如果用户提到了多个位置，告知扫描器每次只能扫描一个，并询问先扫描哪个。

### 2. 执行扫描

将用户提供的输入代入命令并执行。由于 LLM 分析可能需要较长时间，设置较长的超时时间（最多 10000 分钟）。提前告知用户需要等待。

如果命令执行失败：
- 检查 `skill-scanner` 是否已安装——运行安装脚本重新安装
- 检查 LLM API key 是否配置——`--use-llm` 需要 `ANTHROPIC_API_KEY` 或 `OPENAI_API_KEY` 环境变量
- 如果没有 API key，建议用户去掉 `--use-llm` 和 `--enable-meta` 参数，仅使用模式匹配扫描（仍能检测大部分威胁）

### 3. 展示结果

扫描完成后，运行后处理脚本（一次命令完成计行数 + 提取 + 格式化输出）：

```bash
uv --directory "$SKILL_DIR" run python parse_scan_result.py scan_result-<timestamp>.csv
```

**脚本输出说明：**

- 若输出以 `TOO_MANY_RECORDS` 开头（记录数 > 11），直接告知用户"完整结果已保存到: scan_result-<timestamp>.csv，请自行查看"
- 否则脚本会输出格式化的中文摘要，直接将结果展示给用户

**脚本输出的摘要包含：**

- `=== 安全扫描结果 ===` 摘要块：skill 名称、文件位置、结论、最高严重等级、发现问题数、风险等级、评估说明
- 按严重等级分组的发现列表（CRITICAL 在最前面）
- CSV 文件位置

### 4. 解读发现

帮助用户理解扫描结果：

* **skill_verdict字段：**

  * **MALICIOUS** ：skill 大概率不安全。用中文解释具体威胁（prompt injection、数据泄露、恶意代码执行等），并建议不要使用。 

  * **SUSPICIOUS**：潜在风险。解释问题含义并建议审查 skill 的源代码。若同时risk_level大于等于HIGH，则skill 大概率不安全，建议不要使用。

  * **SAFE**：skill基本安全。

* **risk_level字段**

  - **CRITICAL/HIGH**：skill 大概率不安全。用中文解释具体威胁（prompt injection、数据泄露、恶意代码执行等），并建议不要使用。

  - **MEDIUM**：潜在风险。解释问题含义并建议审查 skill 的源代码。

  - **LOW/SAFE**：次要观察。通常可以安全使用，但值得留意。


若上面skill_verdict、risk_level字段不可用：

* max_severity

  - **CRITICAL/HIGH**：skill 大概率不安全。用中文解释具体威胁（prompt injection、数据泄露、恶意代码执行等），并建议不要使用。

  - **MEDIUM**：潜在风险。解释问题含义并建议审查 skill 的源代码。

  - **LOW/INFO**：次要观察。通常可以安全使用，但值得留意。

​	

## 注意事项

- 每个SKILL文件扫描大概需要 1分钟，取决于 skill 大小和 LLM 响应速度。提前告知用户需要等待。

- `--use-llm` 需要 API key（`ANTHROPIC_API_KEY` 或 `OPENAI_API_KEY`），可以在"$SKILL_DIR"/.env文件中配置。如果不可用，建议去掉 `--use-llm` 和 `--enable-meta`，仅使用模式匹配扫描。

- CSV 文件默认保存在当前工作目录下的 `scan_result-<timestamp>.csv`。如果用户想保存到其他路径，调整 `--output` 参数即可。

- 与用户的所有交互使用简体中文，保持专业但易懂的语气。

  
