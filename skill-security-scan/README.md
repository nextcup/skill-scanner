# skill-security-scan

基于 [skill-scanner](https://github.com/cisco-ai-defense/skill-scanner) v0.5.3 的 AI Agent Skill 安全扫描工具，用于检测 prompt injection、数据泄露、恶意代码执行等安全威胁。

## 功能

- **三层扫描引擎**: 静态规则（YARA）+ 行为分析（数据流/污点追踪）+ LLM 语义分析
- **17+ 威胁类别**: prompt injection、command injection、data exfiltration、hardcoded secrets、obfuscation、social engineering 等
- **多种输出格式**: CSV、JSON、Markdown、SARIF、HTML、Table
- **灵活策略系统**: strict / balanced / permissive 预设，或自定义 YAML 策略
- **多输入源**: 本地目录、本地 .zip 文件、远程 .zip URL

## 前置要求

- 安装[uv](https://docs.astral.sh/uv/) 包管理器

  ```shell
  # windows安装 uv
  powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
  
  # linux安装 uv
  curl -LsSf https://astral.sh/uv/install.sh | sh
  ```

- (可选) 设置环境变量`ANTHROPIC_API_KEY` 或 `OPENAI_API_KEY` 或者修改scripts/.env文件—— 用于 LLM 分析和META分析（去误报）

## 安装



`uv run python -m `运行时会自动安装 `skill-scanner` 及其依赖。

(可选) 安装skill-scanner、skill-scanner-pre-commit、skill-scanner-api等命令行到~/.local/bin/

```shell
cd skill-security-scan/scripts
uv tool install --index-url https://pypi.tuna.tsinghua.edu.cn/simple  --editable .
```



## 使用方式

### 作为 Claude Code Skill 使用

在 Claude Code 中直接说：

- "扫描这个 skill 是否安全: `D:\skills\my-skill`"
- "检查 skill 安全性: `https://example.com/skill.zip`"
- "帮我看看这个 skill 有没有问题: `./downloads/skill.zip`"

Skill 会自动运行扫描并以中文呈现结果。

### 命令行使用

```bash
# 设置 scripts 目录
SKILL_DIR="$HOME/.claude/skills/skill-security-scan/scripts"

# 完整扫描（目录/多个 skill）
uv --directory "$SKILL_DIR" run --index-url https://pypi.tuna.tsinghua.edu.cn/simple python -m skill_scanner.cli.cli scan-all <INPUT> \
  --use-behavioral --use-llm --format csv --output result.csv \
  --recursive --lenient --enable-meta

# 单个 skill 扫描
uv --directory "$SKILL_DIR" run --index-url https://pypi.tuna.tsinghua.edu.cn/simple python -m skill_scanner.cli.cli scan <INPUT> \
  --use-behavioral --use-llm --format csv --output result.csv \
  --lenient --enable-meta

# 仅模式匹配扫描（无需 API key）
uv --directory "$SKILL_DIR" run --index-url https://pypi.tuna.tsinghua.edu.cn/simple python  -m skill_scanner.cli.cli scan <INPUT> \
  --use-behavioral --format csv --output result.csv --lenient
```

### 其他命令（若已安装skill-scanner、skill-scanner-pre-commit、skill-scanner-api等命令行到~/.local/bin/）

```bash
# 列出可用分析器
skill-scanner list-analyzers

# 生成默认策略文件
skill-scanner generate-policy -o my_policy.yaml

# 交互式配置策略
skill-scanner configure-policy

# 交互式扫描向导
skill-scanner interactive
```

## 输出解读

扫描完成后生成 CSV 文件，关键字段：

| 字段 | 含义 |
|------|------|
| `is_safe` | `True` 表示未发现威胁 |
| `max_severity` | 最高严重等级: CRITICAL > HIGH > MEDIUM > LOW > INFO |
| `risk_level` | Meta 分析风险等级: CRITICAL > HIGH > MEDIUM > LOW > SAFE |
| `skill_verdict` | Meta 分析结论: MALICIOUS > SUSPICIOUS > SAFE |
| `verdict_reasoning` | 结论理由 |

### 判定逻辑

- `skill_verdict >= SUSPICIOUS` 且 `risk_level >= HIGH` — **不安全**，建议不要使用
- `skill_verdict == MALICIOUS` — **不安全**，存在明确威胁
- `skill_verdict == SUSPICIOUS` — 潜在风险，建议审查源代码
- `skill_verdict == SAFE` — **安全**

## 项目结构

```
skill-security-scan/
├── SKILL.md                  # Skill 定义和执行流程
├── evals/evals.json          # 评估测试用例
└── scripts/
    ├── setup.py              # 安装脚本
    ├── pyproject.toml        # 项目配置和依赖
    └── skill_scanner/        # 扫描引擎源码
        ├── cli/              # 命令行接口
        ├── api/              # REST API 服务
        ├── core/             # 核心扫描逻辑
        │   ├── analyzers/    # 各类分析器
        │   ├── reporters/    # 输出格式化
        │   ├── rules/        # YARA 规则引擎
        │   └── static_analysis/  # 静态分析（CFG、污点追踪）
        ├── data/             # 规则、策略、LLM 提示模板
        ├── threats/          # 威胁分类体系
        └── hooks/            # Git pre-commit hook
```

## 配置

### LLM API Key

在 `scripts/` 目录下创建 `.env` 文件：

```
SKILL_SCANNER_LLM_API_KEY=EMPTY
SKILL_SCANNER_LLM_MODEL=openai/Qwen3.5
SKILL_SCANNER_LLM_BASE_URL=http://192.168.42.1:9990/v1
SKILL_SCANNER_LLM_API_VERSION=
```

没有 API key 时可去掉 `--use-llm` 和 `--enable-meta` 参数，仅使用模式匹配扫描，仍能检测大部分威胁。

### 扫描策略

三种预设策略可通过 `--policy` 指定：

- `strict` — 最严格，所有规则启用
- `balanced` — 默认，平衡准确率和召回率
- `permissive` — 宽松，减少误报

```bash
skill-scanner scan <INPUT> --policy strict --use-behavioral --use-llm
```

## 许可证

Apache-2.0, Cisco Systems, Inc.

底层扫描引擎: [cisco-ai-defense/skill-scanner](https://github.com/cisco-ai-defense/skill-scanner)
