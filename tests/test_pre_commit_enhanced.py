"""Tests for hooks/pre_commit.py enhancements: config loading, CLI args, format_finding."""

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from skill_scanner.core.models import Finding, Severity, ThreatCategory


# ---------------------------------------------------------------------------
# load_config
# ---------------------------------------------------------------------------

class TestLoadConfig:
    def test_loads_json_with_python_booleans(self, tmp_path: Path):
        from skill_scanner.hooks.pre_commit import load_config

        config_file = tmp_path / ".skill_scannerrc"
        config_file.write_text('{ "fail_fast": True, "use_llm": False }')
        cfg = load_config(tmp_path)
        assert cfg["fail_fast"] is True
        assert cfg["use_llm"] is False

    def test_strips_comments(self, tmp_path: Path):
        from skill_scanner.hooks.pre_commit import load_config

        config_file = tmp_path / ".skill_scannerrc"
        config_file.write_text('{ "severity_threshold": "high" # strict mode\n}')
        cfg = load_config(tmp_path)
        assert cfg["severity_threshold"] == "high"

    def test_default_config_values(self, tmp_path: Path):
        from skill_scanner.hooks.pre_commit import load_config, DEFAULT_CONFIG

        cfg = load_config(tmp_path)
        assert cfg["fail_fast"] is False
        assert cfg["use_llm"] is False
        assert cfg["enable_meta"] is False
        assert cfg["use_behavioral"] is False
        assert cfg["use_trigger"] is True

    def test_missing_config_returns_defaults(self, tmp_path: Path):
        from skill_scanner.hooks.pre_commit import load_config, DEFAULT_CONFIG

        cfg = load_config(tmp_path)
        for key, value in DEFAULT_CONFIG.items():
            assert cfg[key] == value


# ---------------------------------------------------------------------------
# format_finding
# ---------------------------------------------------------------------------

class TestFormatFinding:
    def test_basic_finding(self):
        from skill_scanner.hooks.pre_commit import format_finding

        result = format_finding({
            "severity": "high",
            "title": "Test Issue",
            "file_path": "/path/to/file.py",
            "line_number": 42,
            "rule_id": "RULE_001",
        })
        assert "[HIGH]" in result
        assert "Test Issue" in result
        assert "/path/to/file.py:42" in result

    def test_analyzer_tag(self):
        from skill_scanner.hooks.pre_commit import format_finding

        result = format_finding({
            "severity": "critical",
            "title": "Injection",
            "analyzer": "static",
        })
        assert "(static)" in result

    def test_truncates_long_description(self):
        from skill_scanner.hooks.pre_commit import format_finding

        long_desc = "A" * 300
        result = format_finding({
            "severity": "medium",
            "title": "T",
            "description": long_desc,
        })
        assert "..." in result
        # Should be truncated to ~200 chars
        for line in result.splitlines():
            if line.strip().startswith("Detail:"):
                assert len(line.strip()) <= 220

    def test_unknown_location_when_no_file_path(self):
        from skill_scanner.hooks.pre_commit import format_finding

        result = format_finding({"severity": "low", "title": "T"})
        assert "<unknown>" in result

    def test_includes_snippet_and_remediation(self):
        from skill_scanner.hooks.pre_commit import format_finding

        result = format_finding({
            "severity": "high",
            "title": "T",
            "snippet": "eval(user_input)",
            "remediation": "Use ast.literal_eval instead",
        })
        assert "eval(user_input)" in result
        assert "Use ast.literal_eval instead" in result


# ---------------------------------------------------------------------------
# main CLI argument parsing
# ---------------------------------------------------------------------------

class TestMainCLIArgs:
    def test_use_llm_flag(self, tmp_path: Path):
        from skill_scanner.hooks.pre_commit import main

        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
        # Use --all with empty skills path to avoid skill scanning
        exit_code = main(["--skills-path", str(tmp_path / "nonexistent"), "--all", "--use-llm"])
        # Should not crash; exit 0 (no skills to scan)
        assert exit_code == 0

    def test_enable_meta_flag(self, tmp_path: Path):
        from skill_scanner.hooks.pre_commit import main

        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
        exit_code = main(["--skills-path", str(tmp_path / "nonexistent"), "--all", "--enable-meta"])
        assert exit_code == 0

    def test_policy_flag(self, tmp_path: Path):
        from skill_scanner.hooks.pre_commit import main

        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
        exit_code = main(["--skills-path", str(tmp_path / "nonexistent"), "--all", "--policy", "balanced"])
        assert exit_code == 0


# ---------------------------------------------------------------------------
# Severity filtering (only show findings >= threshold)
# ---------------------------------------------------------------------------

class TestSeverityFiltering:
    def test_default_threshold_is_high(self):
        from skill_scanner.hooks.pre_commit import DEFAULT_CONFIG

        assert DEFAULT_CONFIG["severity_threshold"] == "high"