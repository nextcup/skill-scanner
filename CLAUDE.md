# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目概述

Skill Scanner 是一个 AI Agent Skills 的安全扫描器，检测提示词注入、数据泄露和恶意代码模式。采用多引擎检测方式：模式匹配（YAML + YARA）、LLM 语义分析、行为数据流分析。

## 常用命令

### 环境设置

```bash
# 安装依赖（使用 uv 包管理器）
uv sync --all-extras

# 安装 pre-commit hooks
uv run pre-commit install
```

### 测试

```bash
# 运行所有单元测试
uv run pytest tests/ -v --tb=short

# 运行特定测试文件
uv run pytest tests/test_scanner.py -v

# 运行特定测试方法
uv run pytest tests/test_scanner.py::TestScanner::test_scan_safe_skill -v

# 运行带覆盖率的测试
uv run pytest tests/ --cov=skill_scanner --cov-report=html

# 运行分析器特定测试
uv run pytest tests/behavioral/ -v
uv run pytest tests/static_analysis/ -v
```

### 代码质量检查

```bash
# 运行所有 pre-commit 检查
uv run pre-commit run --all-files

# 类型检查
uv run mypy skill_scanner
```

### 评估基准

```bash
# 运行评估基准
uv run python evals/runners/benchmark_runner.py

# 运行完整评估套件
uv run python evals/runners/eval_runner.py --test-skills-dir evals/skills
```

### CLI 使用

```bash
# 核心分析器扫描
skill-scanner scan /path/to/skill

# 启用行为分析器
skill-scanner scan /path/to/skill --use-behavioral

# 启用所有引擎
skill-scanner scan /path/to/skill --use-behavioral --use-llm --use-aidefense

# 生成 SARIF 输出用于 CI/CD
skill-scanner scan-all ./skills --fail-on-severity high --format sarif --output results.sarif
```

## 架构

### 两阶段扫描流水线

1. **Phase 1 (非 LLM)**: static, bytecode, pipeline, behavioral, VirusTotal, AI Defense, trigger 分析器
2. **Phase 2 (LLM/meta)**: LLM 和 meta 分析器，接收 Phase 1 的丰富上下文
3. **后处理**: 规则禁用执行、严重性覆盖、可分析性评分、发现结果归一化/去重

### 核心组件

| 组件 | 路径 | 职责 |
|------|------|------|
| `SkillScanner` | `core/scanner.py` | 扫描编排器，执行两阶段流水线 |
| `SkillLoader` | `core/loader.py` | 加载和验证 skill 目录、解析 SKILL.md |
| `ScanPolicy` | `core/scan_policy.py` | 策略引擎，文件限制、规则范围、严重性覆盖 |
| `AnalyzerFactory` | `core/analyzer_factory.py` | 分析器工厂，统一构建分析器实例 |

### 分析器

| 分析器 | 检测方法 | 入口文件 |
|--------|----------|----------|
| Static | YAML 签名 + YARA 规则 | `core/analyzers/static.py` |
| Bytecode | .pyc 完整性验证 | `core/analyzers/bytecode_analyzer.py` |
| Pipeline | Shell 管道污点分析 | `core/analyzers/pipeline_analyzer.py` |
| Behavioral | AST 数据流分析 | `core/analyzers/behavioral_analyzer.py` |
| LLM | 语义威胁分析 | `core/analyzers/llm_analyzer.py` |
| Meta | 误报过滤 | `core/analyzers/meta_analyzer.py` |
| VirusTotal | 二进制哈希查询 | `core/analyzers/virustotal_analyzer.py` |
| AI Defense | Cisco 云端检测 | `core/analyzers/aidefense_analyzer.py` |
| Trigger | 过宽触发器检查 | `core/analyzers/trigger_analyzer.py` |

### 数据和规则

- **规则包**: `skill_scanner/data/packs/core/` - 签名、YARA 规则、Python 检查模块
- **LLM Prompts**: `skill_scanner/data/prompts/` - LLM 分析提示词
- **策略预设**: `skill_scanner/data/*_policy.yaml` - strict/balanced/permissive

### 扩展点

添加新分析器：
1. 创建继承 `BaseAnalyzer` 的分析器类
2. 在 `analyzer_factory.py` 中注册构建路径
3. 在 `scan_policy.py` 中添加策略开关（如需要）
4. 在 `tests/` 下添加测试

## 数据模型

主数据结构定义在 `core/models.py`:
- `SkillManifest`, `SkillFile`, `Skill` - Skill 包结构
- `Finding`, `ScanResult`, `Report` - 扫描结果
- 枚举: `Severity`, `ThreatCategory`

## 入口点

| 入口 | 命令 | 源文件 |
|------|------|--------|
| CLI | `skill-scanner` | `cli/cli.py` |
| API | `skill-scanner-api` | `api/api_cli.py` |
| Pre-commit | `skill-scanner-pre-commit` | `hooks/pre_commit.py` |

## 提交规范

- 提交消息遵循 conventional commits 格式（如 `feat:`, `fix:`, `docs:`）
- **不要**在 git commits 中添加 AI co-author（如 `Co-authored-by: Cursor`）
- PR 前确保：
  - 所有 pre-commit hooks 通过
  - 所有单元测试通过
  - 基准测试无显著回归
  - 新功能有对应测试

## 配置文件

- `pyproject.toml` - 项目配置、依赖、工具设置
- `.pre-commit-config.yaml` - Pre-commit hooks 配置
- `skill_scanner/data/default_policy.yaml` - 默认扫描策略