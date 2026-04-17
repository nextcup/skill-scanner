"""Tests for config.py: _find_env_file() and load_dotenv()."""

import os
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# _find_env_file
# ---------------------------------------------------------------------------

class TestFindEnvFile:
    def test_finds_env_in_current_dir(self, tmp_path: Path):
        from skill_scanner.config.config import _find_env_file

        (tmp_path / ".env").write_text("KEY=val\n")
        result = _find_env_file(tmp_path)
        assert result is not None
        assert result.name == ".env"

    def test_finds_env_in_parent_dir(self, tmp_path: Path):
        from skill_scanner.config.config import _find_env_file

        (tmp_path / ".env").write_text("KEY=val\n")
        child = tmp_path / "sub"
        child.mkdir()
        result = _find_env_file(child)
        assert result is not None
        assert result == (tmp_path / ".env").resolve()

    def test_finds_env_grandparent(self, tmp_path: Path):
        from skill_scanner.config.config import _find_env_file

        (tmp_path / ".env").write_text("KEY=val\n")
        deep = tmp_path / "a" / "b" / "c"
        deep.mkdir(parents=True)
        result = _find_env_file(deep)
        assert result is not None

    def test_returns_none_when_no_env(self, tmp_path: Path):
        from skill_scanner.config.config import _find_env_file

        assert _find_env_file(tmp_path) is None

    def test_respects_max_depth(self, tmp_path: Path):
        from skill_scanner.config.config import _find_env_file

        # .env is 3 levels up, but max_depth=2
        (tmp_path / ".env").write_text("KEY=val\n")
        deep = tmp_path / "a" / "b" / "c"
        deep.mkdir(parents=True)
        result = _find_env_file(deep, max_depth=2)
        assert result is None

    def test_custom_filename(self, tmp_path: Path):
        from skill_scanner.config.config import _find_env_file

        (tmp_path / "production.env").write_text("KEY=val\n")
        result = _find_env_file(tmp_path, filename="production.env")
        assert result is not None


# ---------------------------------------------------------------------------
# load_dotenv
# ---------------------------------------------------------------------------

class TestLoadDotenv:
    def test_sets_env_var(self, tmp_path: Path):
        from skill_scanner.config.config import load_dotenv

        env = tmp_path / ".env"
        env.write_text("TEST_SK_LOAD_DOTENV_1=hello\n")
        os.environ.pop("TEST_SK_LOAD_DOTENV_1", None)
        load_dotenv(env)
        assert os.environ["TEST_SK_LOAD_DOTENV_1"] == "hello"
        del os.environ["TEST_SK_LOAD_DOTENV_1"]

    def test_does_not_override_existing(self, tmp_path: Path):
        from skill_scanner.config.config import load_dotenv

        os.environ["TEST_SK_LOAD_DOTENV_2"] = "original"
        env = tmp_path / ".env"
        env.write_text("TEST_SK_LOAD_DOTENV_2=overridden\n")
        load_dotenv(env)
        assert os.environ["TEST_SK_LOAD_DOTENV_2"] == "original"
        del os.environ["TEST_SK_LOAD_DOTENV_2"]

    def test_skips_comments_and_blanks(self, tmp_path: Path):
        from skill_scanner.config.config import load_dotenv

        env = tmp_path / ".env"
        env.write_text("# comment\n\n  \nTEST_SK_LOAD_DOTENV_3=val\n")
        os.environ.pop("TEST_SK_LOAD_DOTENV_3", None)
        load_dotenv(env)
        assert os.environ["TEST_SK_LOAD_DOTENV_3"] == "val"
        del os.environ["TEST_SK_LOAD_DOTENV_3"]

    def test_no_env_file_is_noop(self, tmp_path: Path):
        from skill_scanner.config.config import load_dotenv

        # Should not raise
        load_dotenv(tmp_path / "nonexistent.env")

    def test_none_path_searches_upward(self, tmp_path: Path, monkeypatch):
        from skill_scanner.config.config import load_dotenv

        env = tmp_path / ".env"
        env.write_text("TEST_SK_LOAD_DOTENV_4=searched\n")
        os.environ.pop("TEST_SK_LOAD_DOTENV_4", None)
        # Point __file__ to a child directory so the search finds tmp_path/.env
        monkeypatch.setattr(
            "skill_scanner.config.config.__file__", str(tmp_path / "child" / "config.py")
        )
        load_dotenv()
        assert os.environ.get("TEST_SK_LOAD_DOTENV_4") == "searched"
        os.environ.pop("TEST_SK_LOAD_DOTENV_4", None)

    def test_value_with_equals_sign(self, tmp_path: Path):
        from skill_scanner.config.config import load_dotenv

        env = tmp_path / ".env"
        env.write_text("TEST_SK_LOAD_DOTENV_5=key=val=ue\n")
        os.environ.pop("TEST_SK_LOAD_DOTENV_5", None)
        load_dotenv(env)
        assert os.environ["TEST_SK_LOAD_DOTENV_5"] == "key=val=ue"
        del os.environ["TEST_SK_LOAD_DOTENV_5"]