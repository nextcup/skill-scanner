# Copyright 2026 Cisco Systems, Inc.
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

"""Tests for ZipDownloader."""

import io
import tempfile
import urllib.error
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from skill_scanner.core.exceptions import SkillLoadError
from skill_scanner.core.zip_downloader import ZipDownloader


class TestZipDownloader:
    """Test suite for ZipDownloader class."""

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
        assert str(result).startswith(tempfile.gettempdir()) or str(result).startswith(str(tmp_path))
        # evil.py 不应该在父目录中
        evil_path = Path(tempfile.gettempdir()).parent / "evil.py"
        assert not evil_path.exists()

    def test_extract_zip_nonexistent_file(self, tmp_path):
        """不存在的文件应抛出异常"""
        nonexistent = tmp_path / "does_not_exist.zip"
        downloader = ZipDownloader()
        with pytest.raises(SkillLoadError) as exc_info:
            downloader.extract_zip(nonexistent)
        assert "not found" in str(exc_info.value)

    def test_download_and_extract_success(self, tmp_path):
        """下载 URL 并解压"""
        # 创建测试 ZIP 内容
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w') as zf:
            zf.writestr("skill/SKILL.md", "---\nname: test\ndescription: test\n---\ntest")
        zip_buffer.seek(0)

        downloader = ZipDownloader()

        # Mock urllib.request.urlopen to return our test ZIP
        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_response = MagicMock()
            mock_response.read.return_value = zip_buffer.getvalue()
            mock_urlopen.return_value.__enter__.return_value = mock_response

            result = downloader.download_and_extract("https://wry-manatee-359.convex.site/api/v1/download?slug=self-improving-agent")

        assert result.exists()
        assert result.is_dir()

    def test_download_and_extract_network_error(self):
        """网络错误应抛出 SkillLoadError"""
        downloader = ZipDownloader()

        # Mock urllib.request.urlopen to raise a network error
        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_urlopen.side_effect = urllib.error.URLError("Name or service not known")
            with pytest.raises(SkillLoadError) as exc_info:
                downloader.download_and_extract("https://invalid.domainthatdoesnot-exist.example/file.zip")
        assert "Failed to download" in str(exc_info.value)

    def test_download_and_extract_invalid_url(self):
        """非 HTTP URL 应抛出异常"""
        downloader = ZipDownloader()
        with pytest.raises(SkillLoadError) as exc_info:
            downloader.download_and_extract("file:///path/to/local/file.zip")
        assert "Invalid URL" in str(exc_info.value)

    def test_cleanup(self, tmp_path):
        """清理临时目录"""
        # 创建一个临时目录
        temp_dir = Path(tempfile.mkdtemp())
        (temp_dir / "test_file.txt").write_text("test")

        downloader = ZipDownloader()
        downloader.cleanup(temp_dir)

        assert not temp_dir.exists()

    def test_cleanup_nonexistent(self):
        """清理不存在的目录应不抛异常"""
        downloader = ZipDownloader()
        # 不应抛出异常
        downloader.cleanup("/path/that/does/not/exist")

    def test_extract_zip_empty_file(self, tmp_path):
        """解压空 ZIP 文件应返回空目录"""
        # 创建空 ZIP 文件
        zip_path = tmp_path / "empty.zip"
        with zipfile.ZipFile(zip_path, 'w') as zf:
            pass  # 空 ZIP，无任何内容

        downloader = ZipDownloader()
        result = downloader.extract_zip(zip_path)

        assert result.exists()
        assert result.is_dir()
        # 空 ZIP 应创建空目录
        assert list(result.iterdir()) == []