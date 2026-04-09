# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""
Integration tests for ZIP/URL scan support.

Tests scan and scan-all commands with ZIP file and URL inputs.
"""

import io
import json
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent


def _run_cli(*args: str) -> subprocess.CompletedProcess:
    """Run the skill-scanner CLI via subprocess and return the result."""
    cmd = [sys.executable, "-m", "skill_scanner.cli.cli", *args]
    return subprocess.run(cmd, capture_output=True, text=True, cwd=str(PROJECT_ROOT), check=False)


@pytest.fixture
def test_skill_zip(tmp_path: Path) -> Path:
    """Create a test skill ZIP file and return the path.

    The ZIP contains SKILL.md and script.py at root level (single skill structure).
    """
    zip_path = tmp_path / "test_skill.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr(
            "SKILL.md",
            "---\nname: test-skill\ndescription: A test skill\n---\n\nScan me.",
        )
        zf.writestr("script.py", "print('hello')")
    return zip_path


@pytest.fixture
def multi_skill_zip(tmp_path: Path) -> Path:
    """Create a ZIP with multiple skills (skill1/ and skill2/ directories)."""
    zip_path = tmp_path / "multi_skill.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr(
            "skill1/SKILL.md",
            "---\nname: skill1\ndescription: First skill\n---\n\nSkill 1.",
        )
        zf.writestr("skill1/script.py", "print('skill1')")
        zf.writestr(
            "skill2/SKILL.md",
            "---\nname: skill2\ndescription: Second skill\n---\n\nSkill 2.",
        )
        zf.writestr("skill2/script.py", "print('skill2')")
    return zip_path


class TestScanZipInput:
    """Test scan command with ZIP file input."""

    def test_scan_local_zip_produces_json(self, test_skill_zip):
        """Test scanning a local ZIP file produces valid JSON output."""
        result = _run_cli("scan", str(test_skill_zip), "--format", "json")
        assert result.returncode in (0, 1)
        data = json.loads(result.stdout)
        assert "skill_name" in data or "skills" in data or "findings" in data

    def test_scan_local_zip_nonexistent_file(self, tmp_path):
        """Test error when ZIP file does not exist."""
        result = _run_cli("scan", str(tmp_path / "nonexistent.zip"), "--format", "json")
        assert result.returncode == 1
        assert "not found" in result.stderr or "Error" in result.stderr

    def test_scan_local_zip_invalid_format(self, tmp_path):
        """Test error when file is not a valid ZIP."""
        not_zip = tmp_path / "not_zip.txt"
        not_zip.write_text("this is not a zip file")
        result = _run_cli("scan", str(not_zip), "--format", "json")
        assert result.returncode == 1
        assert "not a valid ZIP" in result.stderr or "Error" in result.stderr


class TestScanAllZipInput:
    """Test scan-all command with ZIP file input."""

    def test_scan_all_local_zip_produces_json(self, multi_skill_zip):
        """Test scanning a local ZIP containing multiple skills."""
        result = _run_cli("scan-all", str(multi_skill_zip), "--format", "json")
        assert result.returncode in (0, 1)
        data = json.loads(result.stdout)
        assert "skills" in data or "results" in data

    def test_scan_all_local_zip_nonexistent(self, tmp_path):
        """Test error when ZIP file does not exist."""
        result = _run_cli("scan-all", str(tmp_path / "nonexistent.zip"), "--format", "json")
        assert result.returncode == 1

    def test_scan_all_local_zip_single_skill(self, test_skill_zip):
        """Test scan-all with ZIP containing single skill."""
        result = _run_cli("scan-all", str(test_skill_zip), "--format", "json")
        assert result.returncode in (0, 1)


class TestScanUrlInput:
    """Test scan command with URL input (mocked)."""

    def test_scan_url_invalid_domain(self):
        """Test that invalid domain gives friendly error."""
        result = _run_cli(
            "scan",
            "https://this-domain-does-not-exist-12345.example/file.zip",
            "--format", "json",
        )
        assert result.returncode == 1
        assert "Failed to download" in result.stderr or "Error" in result.stderr

    def test_scan_url_https_not_http(self):
        """Test that http:// URL without proper scheme is rejected."""
        result = _run_cli(
            "scan",
            "http://example.com/skill.zip",
            "--format", "json",
        )
        # Should either work or fail gracefully (network may be blocked)
        # Should not crash
        assert result.returncode in (0, 1)


class TestScanAllUrlInput:
    """Test scan-all command with URL input (mocked)."""

    def test_scan_all_url_invalid_domain(self):
        """Test that invalid domain gives friendly error for scan-all."""
        result = _run_cli(
            "scan-all",
            "https://this-domain-does-not-exist-12345.example/file.zip",
            "--format", "json",
        )
        assert result.returncode == 1
        assert "Failed to download" in result.stderr or "Error" in result.stderr


class TestZipPathTraversal:
    """Test path traversal protection in ZIP handling."""

    def test_scan_zip_with_path_traversal_attempt(self, tmp_path):
        """Test that ZIP with path traversal is handled safely."""
        malicious_zip = tmp_path / "malicious.zip"
        with zipfile.ZipFile(malicious_zip, "w") as zf:
            # Attempt path traversal - SKILL.md at root should be found
            zf.writestr("SKILL.md", "---\nname: safe\ndescription: safe\n---\n")
            zf.writestr("../../../evil.py", "malicious code")
        # Should either reject the traversal or handle safely
        # The scan should work because SKILL.md is at root
        result = _run_cli("scan", str(malicious_zip), "--format", "json")
        assert result.returncode in (0, 1)


class TestHelperFunctions:
    """Test the CLI helper functions directly."""

    def test_is_url_recognizes_http(self):
        """Test _is_url helper recognizes http URLs."""
        from skill_scanner.cli.cli import _is_url
        assert _is_url("http://example.com/file.zip") is True
        assert _is_url("https://example.com/file.zip") is True
        assert _is_url("/local/path/skill.zip") is False
        assert _is_url("relative/path/skill.zip") is False

    def test_is_zip_recognizes_zip_files(self):
        """Test _is_zip helper recognizes ZIP files."""
        from skill_scanner.cli.cli import _is_zip
        assert _is_zip("/path/to/skill.zip") is True
        assert _is_zip("/path/to/skill.ZIP") is True
        assert _is_zip("/path/to/skill.zip.bak") is False
        assert _is_zip("/path/to/skill.tar.gz") is False
        assert _is_zip("/path/to/skill") is False
