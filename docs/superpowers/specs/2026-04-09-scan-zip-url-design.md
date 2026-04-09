# Design: scan 命令支持 ZIP 文件和 URL 输入

**日期:** 2026-04-09
**状态:** 已批准

## 概述

扩展 `scan` 和 `scan-all` 命令，支持直接扫描 ZIP 文件路径和 HTTP/HTTPS URL 来源的 skill 包。

## 动机

当前 `scan` 命令仅支持本地目录路径。用户需要能够：
- 扫描本地 ZIP 文件中的 skill 包
- 通过 URL 直接扫描远程发布的 skill 包（无需先下载到本地）

## 需求

### 输入类型

支持三种输入路径类型：
1. **本地目录** — 现有行为，保持不变
2. **本地 ZIP 文件** — 以 `.zip` 结尾的本地路径
3. **远程 URL** — 以 `http://` 或 `https://` 开头的 URL

### ZIP 文件处理

- 使用 Python 标准库 `zipfile` 解压
- 自动检测 ZIP 根目录结构
- 支持单层（ZIP 内容为 skill 目录）和多层（ZIP 根下有多个 skill）结构
- **注意:** 仅支持 `.zip` 格式

### URL 处理

- 自动识别 URL 输入（以 `http://` 或 `https://` 开头）
- 下载到系统临时目录，使用 `tempfile` 模块
- 支持 HTTP/HTTPS URL
- **注意:** 不支持 Git 仓库 URL（如 `https://github.com/user/repo`），仅支持直接 ZIP 文件下载

### 临时文件管理

- 使用 Python `tempfile` 模块创建临时目录
- 扫描完成后自动清理（使用 `finally` 块确保）
- 临时文件存在于系统临时目录中，生命周期仅限本次扫描

### 错误处理

- 网络错误（连接超时、DNS 失败、404、500 等）：快速失败，打印清晰错误信息，exit code 1
- ZIP 格式错误：打印错误信息，exit code 1
- 解压失败：打印错误信息，exit code 1

### scan-all 命令

`scan-all` 命令同样支持 URL 和 ZIP 输入：
- `scan-all https://example.com/skills.zip` — 下载并扫描 ZIP 内的所有 skills
- `scan-all ./skills.zip` — 扫描本地 ZIP 内的所有 skills
- `scan-all ./local-dir` — 现有行为，扫描本地目录

## 架构

### 新增组件

**`core/zip_downloader.py` — ZipDownloader 类**

```
ZipDownloader
├── download_and_extract(url: str) -> Path
│   └── 下载 URL 到临时 zip 文件，解压，返回内容目录路径
├── extract_zip(zip_path: Path) -> Path
│   └── 解压本地 ZIP 文件，返回内容目录路径
└── _cleanup(path: Path) -> None
    └── 递归删除临时目录
```

**设计说明：**
- `download_and_extract()`：用于 URL 输入，下载并解压到临时目录
- `extract_zip()`：用于本地 ZIP 文件输入，解压到临时目录
- 两者都返回解压后的内容目录路径，由调用方决定如何处理该路径

**关键设计：**
- 职责单一：仅处理下载、解压、清理
- 不负责判断输入类型（由 CLI 层判断）
- 使用标准库 `urllib.request`、`zipfile`、`tempfile`、`shutil`

### CLI 层修改

**`cli/cli.py` — 新增辅助函数**

```python
def _is_url(path: str) -> bool:
    """判断路径是否为 HTTP/HTTPS URL"""
    return path.startswith(("http://", "https://"))

def _is_zip(path: str) -> bool:
    """判断路径是否为本地 ZIP 文件"""
    return Path(path).suffix.lower() == ".zip"

def _resolve_skill_input(path: str) -> Path:
    """检测路径类型并返回本地目录路径"""
    if _is_url(path):
        downloader = ZipDownloader()
        return downloader.download_and_extract(path)
    elif _is_zip(path):
        downloader = ZipDownloader()
        return downloader.extract_zip(Path(path))
    return Path(path)
```

### 命令修改

**scan 命令 (`scan_command`)**
- 第 369 行附近：`skill_dir = Path(args.skill_directory)` 改为 `skill_dir = _resolve_skill_input(args.skill_directory)`
- 在函数入口处执行 resolve，函数末尾添加 finally 块清理临时目录（如果创建了临时目录）

**scan-all 命令 (`scan_all_command`)**
- 类似处理：在调用 `scanner.scan_directory()` 前 resolve 输入路径
- 如果输入是 URL 或 ZIP，扫描完成后清理临时目录

### 临时目录生命周期追踪

```python
_temp_dir: Path | None = None

try:
    skill_dir = _resolve_skill_input(args.skill_directory)
    if _is_url(args.skill_directory) or _is_zip(args.skill_directory):
        _temp_dir = skill_dir  # 记录需要清理的临时目录
    # ... 扫描逻辑 ...
finally:
    if _temp_dir and _temp_dir.exists():
        shutil.rmtree(_temp_dir)
```

## 数据流

### scan 命令（URL/ZIP 输入）

```
用户输入 URL/ZIP
    ↓
resolve_skill_input()
    ↓ (如果是 URL)
ZipDownloader.download_and_extract() → 下载并解压到 temp dir
    ↓ (如果是本地 ZIP)
ZipDownloader.extract_zip() → 解压到 temp dir
    ↓
SkillLoader.load_skill(temp_dir) → 加载 skill
    ↓
SkillScanner.scan_skill() → 执行扫描
    ↓
finally: 清理 temp dir
    ↓
输出结果
```

### scan-all 命令（URL/ZIP 输入）

```
用户输入 URL/ZIP
    ↓
resolve_skill_input()
    ↓
ZipDownloader.download_and_extract() → 解压到 temp dir
    ↓
SkillScanner.scan_directory(temp_dir) → 扫描所有 skills
    ↓
finally: 清理 temp dir
    ↓
输出结果
```

## 文件变更

| 文件 | 变更类型 | 描述 |
|------|----------|------|
| `core/zip_downloader.py` | 新增 | ZipDownloader 类 |
| `cli/cli.py` | 修改 | 添加 `_is_url()`、`_is_zip()`、`_resolve_skill_input()`，修改 `scan_command` 和 `scan_all_command` |

## 依赖

- Python 标准库：`urllib.request`、`zipfile`、`tempfile`、`shutil`、`pathlib`
- 无新增外部依赖

## 测试策略

1. **单元测试：** `ZipDownloader` 类的下载、解压、清理逻辑
2. **集成测试：** CLI 层输入类型检测和临时目录生命周期
3. **手动测试：**
   - `scan <本地zip路径>`
   - `scan <https-url>.zip`
   - `scan-all <本地zip路径>`
   - `scan-all <https-url>.zip`

## 风险与缓解

| 风险 | 缓解措施 |
|------|----------|
| ZIP 路径遍历攻击（zip bomb、路径穿越） | 使用 `zipfile.is_zipfile()` 验证，使用 `Path.resolve()` 防止路径穿越 |
| 大文件导致磁盘空间耗尽 | 使用系统临时目录（通常有大小限制），不处理超大文件 |
| 临时文件残留（扫描过程崩溃） | 使用 `finally` 块确保清理；tempfile 目录本身也会被系统定期清理 |