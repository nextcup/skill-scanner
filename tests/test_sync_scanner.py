"""Tests for skill-security-scan/sync_scanner.py."""

import sys
from pathlib import Path

import pytest

# Add skill-security-scan to path
SYNC_DIR = Path(__file__).resolve().parent.parent / "skill-security-scan"
if str(SYNC_DIR) not in sys.path:
    sys.path.insert(0, str(SYNC_DIR))

from sync_scanner import _should_ignore, sync, main, SRC, DST


class TestShouldIgnore:
    def test_pycache_ignored(self):
        assert _should_ignore(Path("__pycache__") / "foo.pyc") is True

    def test_mypy_cache_ignored(self):
        assert _should_ignore(Path(".mypy_cache") / "data") is True

    def test_ruff_cache_ignored(self):
        assert _should_ignore(Path(".ruff_cache") / "0.0.1") is True

    def test_normal_file_not_ignored(self):
        assert _should_ignore(Path("core") / "scanner.py") is False

    def test_nested_pycache_ignored(self):
        assert _should_ignore(Path("core") / "__pycache__" / "scanner.cpython-312.pyc") is True


class TestSync:
    @pytest.fixture(autouse=True)
    def _setup(self, tmp_path: Path, monkeypatch):
        """Create mock SRC and DST directories."""
        self.src = tmp_path / "src" / "skill_scanner"
        self.dst = tmp_path / "dst" / "skill_scanner"
        self.src.mkdir(parents=True)
        self.dst.mkdir(parents=True)
        monkeypatch.setattr("sync_scanner.SRC", self.src)
        monkeypatch.setattr("sync_scanner.DST", self.dst)

    def test_copies_new_file(self):
        (self.src / "new_file.py").write_text("content")
        changed = sync()
        assert Path("new_file.py") in changed
        assert (self.dst / "new_file.py").read_text() == "content"

    def test_copies_modified_file(self):
        (self.src / "mod.py").write_text("v1")
        (self.dst / "mod.py").write_text("v0")
        changed = sync()
        assert Path("mod.py") in changed
        assert (self.dst / "mod.py").read_text() == "v1"

    def test_no_change_returns_empty(self):
        (self.src / "same.py").write_text("same")
        (self.dst / "same.py").write_text("same")
        changed = sync()
        assert Path("same.py") not in changed

    def test_deletes_extra_file_in_dst(self):
        (self.dst / "extra.py").write_text("extra")
        changed = sync()
        assert Path("extra.py") in changed
        assert not (self.dst / "extra.py").exists()

    def test_ignores_pycache(self):
        cache_dir = self.src / "__pycache__"
        cache_dir.mkdir(exist_ok=True)
        (cache_dir / "foo.pyc").write_bytes(b"cache")
        changed = sync()
        assert not (self.dst / "__pycache__").exists()

    def test_copies_nested_structure(self):
        (self.src / "core" / "scanner.py").parent.mkdir(parents=True, exist_ok=True)
        (self.src / "core" / "scanner.py").write_text("code")
        changed = sync()
        assert Path("core") / "scanner.py" in changed

    def test_cleans_empty_dirs(self):
        (self.dst / "empty_dir").mkdir()
        changed = sync()
        assert not (self.dst / "empty_dir").exists()


class TestMain:
    def test_src_not_found(self, tmp_path: Path, monkeypatch):
        monkeypatch.setattr("sync_scanner.SRC", tmp_path / "nonexistent")
        assert main() == 1

    def test_no_changes_returns_0(self, tmp_path: Path, monkeypatch):
        src = tmp_path / "src" / "skill_scanner"
        src.mkdir(parents=True)
        dst = tmp_path / "dst" / "skill_scanner"
        dst.mkdir(parents=True)
        monkeypatch.setattr("sync_scanner.SRC", src)
        monkeypatch.setattr("sync_scanner.DST", dst)
        assert main() == 0