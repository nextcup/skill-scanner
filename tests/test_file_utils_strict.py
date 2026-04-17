"""Tests for file_utils.py: read_text_strict() and FileValidationError."""

from pathlib import Path

import pytest

from skill_scanner.utils.file_utils import FileValidationError, read_text_strict


class TestReadTextStrict:
    def test_reads_utf8_file(self, tmp_path: Path):
        f = tmp_path / "test.txt"
        f.write_text("hello world", encoding="utf-8")
        assert read_text_strict(f) == "hello world"

    def test_strips_bom(self, tmp_path: Path):
        f = tmp_path / "bom.txt"
        f.write_bytes(b"\xef\xbb\xbfhello")
        result = read_text_strict(f)
        assert result == "hello"
        assert not result.startswith("\ufeff")

    def test_rejects_null_bytes(self, tmp_path: Path):
        f = tmp_path / "binary.bin"
        f.write_bytes(b"hello\x00world")
        with pytest.raises(FileValidationError, match="null bytes"):
            read_text_strict(f)

    def test_rejects_non_utf8(self, tmp_path: Path):
        f = tmp_path / "latin.txt"
        f.write_bytes(b"\xff\xfe invalid utf8 \x80\x81")
        with pytest.raises(FileValidationError, match="not valid UTF-8"):
            read_text_strict(f)

    def test_rejects_oversized_file(self, tmp_path: Path):
        f = tmp_path / "big.txt"
        f.write_bytes(b"x" * 100)
        with pytest.raises(FileValidationError, match="exceeds maximum size"):
            read_text_strict(f, max_size_bytes=50)

    def test_nonexistent_file(self, tmp_path: Path):
        with pytest.raises(FileValidationError, match="Failed to read"):
            read_text_strict(tmp_path / "nope.txt")

    def test_max_size_allows_exact_size(self, tmp_path: Path):
        f = tmp_path / "exact.txt"
        content = "abc"
        f.write_text(content, encoding="utf-8")
        # Content is 3 bytes, max_size_bytes=3 should pass
        assert read_text_strict(f, max_size_bytes=3) == content

    def test_unicode_content(self, tmp_path: Path):
        f = tmp_path / "unicode.txt"
        f.write_text("你好世界 🌍", encoding="utf-8")
        assert read_text_strict(f) == "你好世界 🌍"

    def test_empty_file(self, tmp_path: Path):
        f = tmp_path / "empty.txt"
        f.write_text("", encoding="utf-8")
        assert read_text_strict(f) == ""

    def test_no_max_size_by_default(self, tmp_path: Path):
        f = tmp_path / "normal.txt"
        f.write_text("x" * 10000, encoding="utf-8")
        # Should not raise
        assert len(read_text_strict(f)) == 10000