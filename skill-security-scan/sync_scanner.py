#!/usr/bin/env python3
"""将 skill_scanner 源码同步到 scripts/ 目录，用于发布 skill-security-scan。

用法:
    python sync_scanner.py          # 同步源码
    python sync_scanner.py --check  # 仅检查是否过期
"""

import filecmp
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent  # skill-scanner project root
SRC = ROOT / "skill_scanner"
DST = Path(__file__).resolve().parent / "scripts" / "skill_scanner"

# 不同步的目录/文件
IGNORE_PREFIXES = ("__pycache__", ".mypy_cache", ".ruff_cache")


def _should_ignore(rel_path: Path) -> bool:
    return any(part.startswith(IGNORE_PREFIXES) for part in rel_path.parts)


def sync() -> list[Path]:
    """同步源码，返回变更文件列表（相对路径）。"""
    changed: list[Path] = []

    # 复制新增/修改的文件
    for src_file in SRC.rglob("*"):
        if not src_file.is_file():
            continue
        rel = src_file.relative_to(SRC)
        if _should_ignore(rel):
            continue
        dst_file = DST / rel
        dst_file.parent.mkdir(parents=True, exist_ok=True)
        if not dst_file.exists() or not filecmp.cmp(src_file, dst_file, shallow=False):
            shutil.copy2(src_file, dst_file)
            changed.append(rel)

    # 删除目标中多余的文件
    for dst_file in list(DST.rglob("*")):
        if not dst_file.is_file():
            continue
        rel = dst_file.relative_to(DST)
        if _should_ignore(rel):
            continue
        if not (SRC / rel).exists():
            dst_file.unlink()
            changed.append(rel)

    # 清理空目录
    for dst_dir in sorted(DST.rglob("*"), reverse=True):
        if dst_dir.is_dir() and not any(dst_dir.iterdir()):
            dst_dir.rmdir()

    return changed


def main() -> int:
    if not SRC.exists():
        print(f"Error: source not found: {SRC}", file=sys.stderr)
        return 1

    changed = sync()

    if not changed:
        print("Already up to date.")
        return 0

    print(f"Synced {len(changed)} file(s):")
    for f in sorted(changed):
        print(f"  {f}")
    return 0


if __name__ == "__main__":
    if "--check" in sys.argv:
        changed = sync()
        if changed:
            print(f"OUTDATED: {len(changed)} file(s) differ. Run: python sync_scanner.py")
            sys.exit(1)
        print("Up to date.")
        sys.exit(0)
    sys.exit(main())
