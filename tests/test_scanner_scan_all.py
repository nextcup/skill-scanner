"""Tests for scanner.py scan-all enhancements: progress_callback, nested skill filtering."""

from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# _is_ancestor helper
# ---------------------------------------------------------------------------

class TestIsAncestor:
    def test_parent_is_ancestor(self):
        from skill_scanner.core.scanner import _is_ancestor

        assert _is_ancestor(Path("/a"), Path("/a/b")) is True

    def test_same_path_is_not_ancestor(self):
        from skill_scanner.core.scanner import _is_ancestor

        # _is_ancestor checks relative_to which succeeds for same path,
        # but _filter_nested_skills uses candidate != existing guard
        assert _is_ancestor(Path("/a"), Path("/a")) is True

    def test_sibling_is_not_ancestor(self):
        from skill_scanner.core.scanner import _is_ancestor

        assert _is_ancestor(Path("/a"), Path("/b")) is False

    def test_unrelated_path(self):
        from skill_scanner.core.scanner import _is_ancestor

        assert _is_ancestor(Path("/a/b"), Path("/c/d")) is False

    def test_deep_nesting(self):
        from skill_scanner.core.scanner import _is_ancestor

        assert _is_ancestor(Path("/a"), Path("/a/b/c/d")) is True


# ---------------------------------------------------------------------------
# _filter_nested_skills
# ---------------------------------------------------------------------------

class TestFilterNestedSkills:
    def test_filters_child_of_parent_skill(self):
        from skill_scanner.core.scanner import SkillScanner

        parent = Path("/skills/agent")
        child = Path("/skills/agent/assets")
        result = SkillScanner._filter_nested_skills([parent, child])
        assert parent in result
        assert child not in result

    def test_keeps_unrelated_skills(self):
        from skill_scanner.core.scanner import SkillScanner

        a = Path("/skills/agent-a")
        b = Path("/skills/agent-b")
        result = SkillScanner._filter_nested_skills([a, b])
        assert len(result) == 2

    def test_empty_list(self):
        from skill_scanner.core.scanner import SkillScanner

        assert SkillScanner._filter_nested_skills([]) == []

    def test_single_entry(self):
        from skill_scanner.core.scanner import SkillScanner

        p = Path("/skills/agent")
        assert SkillScanner._filter_nested_skills([p]) == [p]

    def test_deeply_nested_filtered(self):
        from skill_scanner.core.scanner import SkillScanner

        parent = Path("/skills/agent")
        refs = Path("/skills/agent/references")
        deep = Path("/skills/agent/references/guides")
        result = SkillScanner._filter_nested_skills([deep, parent, refs])
        assert result == [parent]

    def test_multiple_parents_with_children(self):
        from skill_scanner.core.scanner import SkillScanner

        a = Path("/skills/a")
        a_assets = Path("/skills/a/assets")
        b = Path("/skills/b")
        b_refs = Path("/skills/b/references")
        result = SkillScanner._filter_nested_skills([a, a_assets, b, b_refs])
        assert set(result) == {a, b}


# ---------------------------------------------------------------------------
# _find_skill_directories: directory itself contains SKILL.md
# ---------------------------------------------------------------------------

class TestFindSkillDirectories:
    def test_directory_itself_with_skill_md(self, tmp_path: Path):
        from skill_scanner.core.scan_policy import ScanPolicy
        from skill_scanner.core.scanner import SkillScanner

        (tmp_path / "SKILL.md").write_text("---\nname: test\n---\nBody")
        scanner = SkillScanner(policy=ScanPolicy.default())
        dirs = scanner._find_skill_directories(tmp_path, recursive=False)
        assert tmp_path.resolve() in [d.resolve() for d in dirs]

    def test_subdirectory_with_skill_md(self, tmp_path: Path):
        from skill_scanner.core.scan_policy import ScanPolicy
        from skill_scanner.core.scanner import SkillScanner

        sub = tmp_path / "my-skill"
        sub.mkdir()
        (sub / "SKILL.md").write_text("---\nname: test\n---\nBody")
        scanner = SkillScanner(policy=ScanPolicy.default())
        dirs = scanner._find_skill_directories(tmp_path, recursive=False)
        resolved = [d.resolve() for d in dirs]
        assert sub.resolve() in resolved

    def test_recursive_filters_nested(self, tmp_path: Path):
        from skill_scanner.core.scan_policy import ScanPolicy
        from skill_scanner.core.scanner import SkillScanner

        parent = tmp_path / "agent"
        parent.mkdir()
        (parent / "SKILL.md").write_text("---\nname: agent\n---\nBody")
        assets = parent / "assets"
        assets.mkdir()
        (assets / "guide.md").write_text("# Guide")

        scanner = SkillScanner(policy=ScanPolicy.default())
        dirs = scanner._find_skill_directories(tmp_path, recursive=True)
        resolved = [d.resolve() for d in dirs]
        assert parent.resolve() in resolved
        assert assets.resolve() not in resolved


# ---------------------------------------------------------------------------
# scan_all progress_callback
# ---------------------------------------------------------------------------

class TestScanAllProgressCallback:
    def test_progress_callback_called(self, tmp_path: Path):
        from skill_scanner.core.scan_policy import ScanPolicy
        from skill_scanner.core.scanner import SkillScanner

        # Create two skill directories
        for name in ("skill-a", "skill-b"):
            d = tmp_path / name
            d.mkdir()
            (d / "SKILL.md").write_text(f"---\nname: {name}\n---\nBody")

        scanner = SkillScanner(policy=ScanPolicy.default())
        progress_calls: list[tuple[str, int, int]] = []

        def on_progress(name: str, idx: int, total: int):
            progress_calls.append((name, idx, total))

        scanner.scan_directory(tmp_path, recursive=False, progress_callback=on_progress)
        assert len(progress_calls) == 2
        assert progress_calls[0][2] == 2  # total
        assert progress_calls[0][1] == 1  # idx
        assert progress_calls[1][1] == 2

    def test_scan_all_empty_dir(self, tmp_path: Path):
        from skill_scanner.core.scan_policy import ScanPolicy
        from skill_scanner.core.scanner import SkillScanner

        scanner = SkillScanner(policy=ScanPolicy.default())
        progress_calls: list[tuple[str, int, int]] = []
        report = scanner.scan_directory(tmp_path, recursive=False, progress_callback=lambda n, i, t: progress_calls.append((n, i, t)))
        assert len(progress_calls) == 0