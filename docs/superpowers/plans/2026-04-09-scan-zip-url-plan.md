# scan 命令 ZIP/URL 支持实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 扩展 `scan` 和 `scan-all` 命令，支持 ZIP 文件路径和 HTTP/HTTPS URL 输入

**Architecture:**
- 新增 `ZipDownloader` 类处理下载和解压逻辑
- CLI 层添加输入类型检测辅助函数
- 使用系统临时目录存储解压内容，扫描后自动清理

**Tech Stack:** Python 标准库（`urllib.request`、`zipfile`、`tempfile`、`shutil`）

---

## 文件结构

| 文件 | 职责 |
|------|------|
| `skill_scanner/core/zip_downloader.py` | ZIP 下载、解压、清理逻辑 |
| `skill_scanner/cli/cli.py` | 添加输入检测辅助函数，修改 scan/scan-all 命令 |
| `tests/test_zip_downloader.py` | ZipDownloader 单元测试 |

---

## Task 1: 创建 ZipDownloader 类

**Files:**
- Create: `skill_scanner/core/zip_downloader.py`
- Test: `tests/test_zip_downloader.py`

- [ ] **Step 1: 编写 ZipDownloader 基本结构的测试**

```python
# tests/test_zip_downloader.py
import pytest
import zipfile
import tempfile
from pathlib import Path

from skill_scanner.core.zip_downloader import ZipDownloader


class TestZipDownloader:
    def test_extract_zip_returns_path_to_extracted_dir(self, tmp_path):
        """解压本地 ZIP 文件，返回解压目录路径"""
        # 创建测试 ZIP
        zip_path = tmp_path / "test.zip"
        with zipfile.ZipFile(zip_path, 'w') as zf:
            zf.writestr("skill/SKILL.md", "---\nname: test\ndescription: test\n---\ntest")
            zf.writestr("skill/script.py", "print('hello')")

        downloader = ZipDownloader()
        result = downloader.extract_zip(zip_path)

        assert result.exists()
        assert result.is_dir()
        assert (result / "skill").exists()

    def test_extract_zip_validates_zipfile(self, tmp_path):
        """非 ZIP 文件应抛出异常"""
        not_zip = tmp_path / "not_zip.txt"
        not_zip.write_text("not a zip file")

        downloader = ZipDownloader()
        with pytest.raises(SkillLoadError):
            downloader.extract_zip(not_zip)

    def test_extract_zip_handles_path_traversal(self, tmp_path):
        """防止路径遍历攻击"""
        # 创建包含路径遍历的 ZIP
        zip_path = tmp_path / "malicious.zip"
        with zipfile.ZipFile(zip_path, 'w') as zf:
            zf.writestr("../../../evil.py", "malicious")

        downloader = ZipDownloader()
        result = downloader.extract_zip(zip_path)
        # 文件应在临时目录内，不应逃逸
        assert result in tempfile.gettempdir() or str(result).startswith(str(tmp_path))

    def test_download_and_extract_success(self, tmp_path, httpserver):
        """下载 URL 并解压"""
        import gzip
        import shutil

        # 创建测试 ZIP 内容
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w') as zf:
            zf.writestr("skill/SKILL.md", "---\nname: test\ndescription: test\n---\ntest")
        zip_buffer.seek(0)

        httpserver.expect_request("/test.zip").respond_with_data(zip_buffer.read())
        httpserver.content_type = 'application/zip'

        downloader = ZipDownloader()
        result = downloader.download_and_extract(httpserver.url_for("/test.zip"))

        assert result.exists()
        assert result.is_dir()

    def test_download_and_extract_network_error(self):
        """网络错误应抛出 SkillLoadError"""
        downloader = ZipDownloader()
        with pytest.raises(SkillLoadError) as exc_info:
            downloader.download_and_extract("https://invalid.domainthatdoesnot-exist.example/file.zip")
        assert "Failed to download" in str(exc_info.value)
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cd "D:/proj/PycharmProjects/skill-scanner" && uv run pytest tests/test_zip_downloader.py -v 2>&1 | head -50`
Expected: FAIL - module not found

- [ ] **Step 3: 编写 ZipDownloader 类实现**

```python
# skill_scanner/core/zip_downloader.py
"""
ZIP file downloader and extractor for remote skill packages.
"""

from __future__ import annotations

import io
import logging
import shutil
import tempfile
import urllib.request
import zipfile
from pathlib import Path

from .exceptions import SkillLoadError

logger = logging.getLogger(__name__)


class ZipDownloader:
    """Downloads and extracts skill packages from ZIP files and URLs.

    Uses system temporary directories for storage, which are automatically
    cleaned up after scanning.
    """

    def __init__(self, connect_timeout: float = 30.0):
        """
        Initialize ZipDownloader.

        Args:
            connect_timeout: Connection timeout in seconds for URL downloads.
        """
        self.connect_timeout = connect_timeout

    def download_and_extract(self, url: str) -> Path:
        """
        Download a ZIP file from URL and extract it to a temporary directory.

        Args:
            url: HTTP/HTTPS URL pointing to a ZIP file.

        Returns:
            Path to the directory containing the extracted contents.

        Raises:
            SkillLoadError: If download fails or file is not a valid ZIP.
        """
        if not url.startswith(("http://", "https://")):
            raise SkillLoadError(f"Invalid URL: {url}")

        # Download to a temporary ZIP file
        zip_fd, zip_path = tempfile.mkstemp(suffix=".zip")
        try:
            try:
                with urllib.request.urlopen(url, timeout=self.connect_timeout) as response:
                    zip_data = response.read()
                with open(zip_fd, 'wb') as f:
                    f.write(zip_data)
            except Exception as e:
                raise SkillLoadError(f"Failed to download {url}: {e}") from e
            finally:
                import os
                os.close(zip_fd)

            # Extract the ZIP
            temp_dir = tempfile.mkdtemp()
            try:
                with zipfile.ZipFile(zip_path, 'r') as zf:
                    # Security check: validate it's a real ZIP
                    if not zipfile.is_zipfile(zip_path):
                        raise SkillLoadError(f"Downloaded file is not a valid ZIP: {url}")

                    # Extract with basic path traversal protection
                    for member in zf.namelist():
                        member_path = Path(member)
                        # Reject paths with traversal sequences
                        if member_path.parts and any(p == '..' for p in member_path.parts):
                            logger.warning(f"Skipping path traversal attempt: {member}")
                            continue
                        zf.extract(member, temp_dir)

            except zipfile.BadZipFile as e:
                shutil.rmtree(temp_dir, ignore_errors=True)
                raise SkillLoadError(f"Invalid ZIP file from {url}: {e}") from e

            return Path(temp_dir)

        finally:
            # Clean up the temporary ZIP file
            Path(zip_path).unlink(missing_ok=True)

    def extract_zip(self, zip_path: Path | str) -> Path:
        """
        Extract a local ZIP file to a temporary directory.

        Args:
            zip_path: Path to a local ZIP file.

        Returns:
            Path to the directory containing the extracted contents.

        Raises:
            SkillLoadError: If the file is not a valid ZIP.
        """
        zip_path = Path(zip_path)

        if not zip_path.exists():
            raise SkillLoadError(f"ZIP file not found: {zip_path}")

        if not zipfile.is_zipfile(zip_path):
            raise SkillLoadError(f"Not a valid ZIP file: {zip_path}")

        temp_dir = tempfile.mkdtemp()
        try:
            with zipfile.ZipFile(zip_path, 'r') as zf:
                # Security check: path traversal protection
                for member in zf.namelist():
                    member_path = Path(member)
                    if member_path.parts and any(p == '..' for p in member_path.parts):
                        logger.warning(f"Skipping path traversal attempt: {member}")
                        continue
                    zf.extract(member, temp_dir)

            return Path(temp_dir)

        except zipfile.BadZipFile as e:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise SkillLoadError(f"Invalid ZIP file {zip_path}: {e}") from e

    def cleanup(self, path: Path | str) -> None:
        """
        Recursively delete a temporary directory.

        Args:
            path: Path to directory to delete.
        """
        path = Path(path)
        if path.exists():
            shutil.rmtree(path, ignore_errors=True)
```

- [ ] **Step 4: 运行测试确认通过**

Run: `cd "D:/proj/PycharmProjects/skill-scanner" && uv run pytest tests/test_zip_downloader.py -v`
Expected: PASS（如果使用了 httpserver fixture 需要安装 pytest-httpserver）

- [ ] **Step 5: 提交**

```bash
git add skill_scanner/core/zip_downloader.py tests/test_zip_downloader.py
git commit -m "feat: add ZipDownloader for ZIP/URL extraction

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

## Task 2: 修改 CLI 添加输入类型检测

**Files:**
- Modify: `skill_scanner/cli/cli.py`（在 `_handle_rule_packs_list` 函数前添加辅助函数）

- [ ] **Step 1: 添加辅助函数**

在 `cli.py` 第 340 行（`_handle_rule_packs_list` 函数前）添加：

```python
def _is_url(path: str) -> bool:
    """Check if path is an HTTP/HTTPS URL."""
    return path.startswith(("http://", "https://"))


def _is_zip(path: str) -> bool:
    """Check if path is a local ZIP file."""
    return Path(path).suffix.lower() == ".zip"


def _resolve_skill_input(path: str) -> tuple[Path, Path | None]:
    """
    Resolve skill input path.

    Args:
        path: Input path (directory, ZIP file, or URL)

    Returns:
        Tuple of (resolved_path, temp_dir_to_cleanup).
        temp_dir_to_cleanup is the path that should be cleaned up after scan,
        or None if input was already a local directory.
    """
    from ..core.zip_downloader import ZipDownloader

    downloader = ZipDownloader()

    if _is_url(path):
        temp_dir = downloader.download_and_extract(path)
        return temp_dir, temp_dir
    elif _is_zip(path):
        temp_dir = downloader.extract_zip(Path(path))
        return temp_dir, temp_dir
    else:
        return Path(path), None
```

- [ ] **Step 2: 确认代码放置位置正确**

Run: `grep -n "_handle_rule_packs_list" skill_scanner/cli/cli.py`
Expected: 347

- [ ] **Step 3: 运行测试确认没有破坏现有功能**

Run: `cd "D:/proj/PycharmProjects/skill-scanner" && uv run pytest tests/test_scanner.py -v --tb=short 2>&1 | tail -20`
Expected: PASS

- [ ] **Step 4: 提交**

```bash
git add skill_scanner/cli/cli.py
git commit -m "refactor(cli): add _is_url, _is_zip, _resolve_skill_input helpers

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

## Task 3: 修改 scan_command 支持 ZIP/URL

**Files:**
- Modify: `skill_scanner/cli/cli.py`（修改 `scan_command` 函数）

- [ ] **Step 1: 修改 scan_command 函数**

在 `scan_command` 函数（约第 364 行开始），将：

```python
skill_dir = Path(args.skill_directory)
if not skill_dir.exists():
    print(f"Error: Directory does not exist: {skill_dir}", file=sys.stderr)
    return 1
```

改为：

```python
try:
    skill_dir, temp_dir = _resolve_skill_input(args.skill_directory)
except Exception as e:
    print(f"Error: {e}", file=sys.stderr)
    return 1

if not skill_dir.exists():
    print(f"Error: Directory does not exist: {skill_dir}", file=sys.stderr)
    return 1
```

然后在 `try:` 块（扫描逻辑）后面添加 finally 块清理临时目录：

```python
try:
    # ... existing scan logic ...
except SkillLoadError as e:
    print(f"Error loading skill: {e}", file=sys.stderr)
    return 1
except Exception as e:
    print(f"Unexpected error: {e}", file=sys.stderr)
    traceback.print_exc(file=sys.stderr)
    return 1
finally:
    if temp_dir and temp_dir.exists():
        shutil.rmtree(temp_dir, ignore_errors=True)
```

需要添加 `import shutil`（如果尚未导入）。检查现有的 import 部分。

- [ ] **Step 2: 运行 CLI 帮助确认没有语法错误**

Run: `cd "D:/proj/PycharmProjects/skill-scanner" && uv run python -c "from skill_scanner.cli.cli import main; print('OK')"`
Expected: OK

- [ ] **Step 3: 提交**

```bash
git add skill_scanner/cli/cli.py
git commit -m "feat(scan): support ZIP file and URL inputs

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

## Task 4: 修改 scan_all_command 支持 ZIP/URL

**Files:**
- Modify: `skill_scanner/cli/cli.py`（修改 `scan_all_command` 函数）

- [ ] **Step 1: 修改 scan_all_command 函数**

在 `scan_all_command` 函数（约第 454 行开始），将：

```python
skills_dir = Path(args.skills_directory)
if not skills_dir.exists():
    print(f"Error: Directory does not exist: {skills_dir}", file=sys.stderr)
    return 1
```

改为：

```python
try:
    skills_dir, temp_dir = _resolve_skill_input(args.skills_directory)
except Exception as e:
    print(f"Error: {e}", file=sys.stderr)
    return 1

if not skills_dir.exists():
    print(f"Error: Directory does not exist: {skills_dir}", file=sys.stderr)
    return 1
```

然后在函数末尾（`return 0` 之前）添加 finally 块：

```python
finally:
    if temp_dir and temp_dir.exists():
        shutil.rmtree(temp_dir, ignore_errors=True)
```

同时把 `return 0` 改为在 try 块正常完成后返回。

**注意：** 需要在函数外层加一层 try-finally，因为函数有多个 return 语句。

简化方案：在函数入口用 try 包住所有逻辑：

```python
def scan_all_command(args: argparse.Namespace) -> int:
    temp_dir = None
    try:
        # ... all existing logic ...
        return 0  # or 1
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return 1
    finally:
        if temp_dir and temp_dir.exists():
            shutil.rmtree(temp_dir, ignore_errors=True)
```

- [ ] **Step 2: 运行测试确认没有语法错误**

Run: `cd "D:/proj/PycharmProjects/skill-scanner" && uv run python -c "from skill_scanner.cli.cli import main; print('OK')"`
Expected: OK

- [ ] **Step 3: 提交**

```bash
git add skill_scanner/cli/cli.py
git commit -m "feat(scan-all): support ZIP file and URL inputs

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

## Task 5: 添加 CLI 集成测试

**Files:**
- Create: `tests/test_zip_url_cli.py`

- [ ] **Step 1: 编写 CLI 集成测试**

```python
# tests/test_zip_url_cli.py
"""Integration tests for ZIP/URL scan support."""

import io
import zipfile
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from click.testing import CliRunner

from skill_scanner.cli.cli import cli


class TestScanZipInput:
    """Test scan command with ZIP file input."""

    def test_scan_local_zip(self, tmp_path):
        """Test scanning a local ZIP file."""
        # Create a test skill ZIP
        zip_path = tmp_path / "test_skill.zip"
        with zipfile.ZipFile(zip_path, 'w') as zf:
            zf.writestr("skill/SKILL.md",
                "---\nname: test-skill\ndescription: A test skill\n---\n\nScan me.")
            zf.writestr("skill/script.py", "print('hello')")

        runner = CliRunner()
        result = runner.invoke(cli, ["scan", str(zip_path), "--format", "json"])

        assert result.exit_code in (0, 1)  # 0 if safe, 1 if findings
        # Verify output is valid JSON
        import json
        output = json.loads(result.output)
        assert "skill_name" in output or "skills" in output


class TestScanUrlInput:
    """Test scan command with URL input."""

    def test_scan_url_friendly_error(self, tmp_path, monkeypatch):
        """Test that URL errors give friendly messages."""

        def mock_urlopen(url, timeout=None):
            raise Exception("Connection refused")

        monkeypatch.setattr("urllib.request.urlopen", mock_urlopen)

        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "https://example.com/skill.zip"])

        assert result.exit_code == 1
        assert "Failed to download" in result.output or "Error" in result.output


class TestScanAllZipInput:
    """Test scan-all command with ZIP file input."""

    def test_scan_all_local_zip(self, tmp_path):
        """Test scanning a local ZIP containing multiple skills."""
        # Create a ZIP with multiple skills
        zip_path = tmp_path / "multi_skill.zip"
        with zipfile.ZipFile(zip_path, 'w') as zf:
            zf.writestr("skill1/SKILL.md",
                "---\nname: skill1\ndescription: First skill\n---\n\nSkill 1.")
            zf.writestr("skill1/script.py", "print('skill1')")
            zf.writestr("skill2/SKILL.md",
                "---\nname: skill2\ndescription: Second skill\n---\n\nSkill 2.")
            zf.writestr("skill2/script.py", "print('skill2')")

        runner = CliRunner()
        result = runner.invoke(cli, ["scan-all", str(zip_path), "--format", "json"])

        # Should exit 0 or 1 depending on findings
        assert result.exit_code in (0, 1)
```

- [ ] **Step 2: 运行测试**

Run: `cd "D:/proj/PycharmProjects/skill-scanner" && uv run pytest tests/test_zip_url_cli.py -v --tb=short 2>&1 | tail -30`
Expected: 测试结果

- [ ] **Step 3: 提交**

```bash
git add tests/test_zip_url_cli.py
git commit -m "test: add CLI integration tests for ZIP/URL scan support

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

## Task 6: 最终验证

- [ ] **Step 1: 运行完整测试套件**

Run: `cd "D:/proj/PycharmProjects/skill-scanner" && uv run pytest tests/test_scanner.py tests/test_zip_downloader.py tests/test_zip_url_cli.py -v --tb=short 2>&1 | tail -40`
Expected: PASS

- [ ] **Step 2: 运行 pre-commit 检查**

Run: `cd "D:/proj/PycharmProjects/skill-scanner" && uv run pre-commit run --all-files 2>&1 | tail -20`
Expected: PASS

- [ ] **Step 3: 手动功能测试**

```bash
# 创建测试 ZIP
cd /tmp
mkdir -p test_skill/skill
echo '---
name: test-skill
description: A test skill
---' > test_skill/skill/SKILL.md
echo 'print("hello")' > test_skill/skill/script.py
zip -r test_skill.zip test_skill

# 测试本地 ZIP
skill-scanner scan /tmp/test_skill.zip --format json

# 测试 URL (使用本地服务器或公网 ZIP)
# skill-scanner scan https://example.com/skill.zip
```

---

## 实现检查清单

- [ ] `ZipDownloader` 类创建并通过单元测试
- [ ] `_is_url()`、`_is_zip()`、`_resolve_skill_input()` 辅助函数添加到 CLI
- [ ] `scan_command` 支持 ZIP/URL 输入，临时目录正确清理
- [ ] `scan_all_command` 支持 ZIP/URL 输入，临时目录正确清理
- [ ] CLI 集成测试通过
- [ ] 现有测试套件通过
- [ ] pre-commit 检查通过
- [ ] 手动功能测试通过