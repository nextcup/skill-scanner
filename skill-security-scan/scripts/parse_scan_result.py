#!/usr/bin/env python3
"""扫描结果后处理：读取 CSV、统计记录数、格式化输出中文摘要。

用法: python parse_scan_result.py <csv_file>
"""

import csv
import json
import sys

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_LABELS = {
    "CRITICAL": "CRITICAL — 严重",
    "HIGH": "HIGH — 高危",
    "MEDIUM": "MEDIUM — 中危",
    "LOW": "LOW — 低危",
    "INFO": "INFO — 信息",
}
VERDICT_ORDER = {"SAFE": 0, "SUSPICIOUS": 1, "MALICIOUS": 2}
RISK_ORDER = {"SAFE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def format_findings(findings: list[dict]) -> None:
    """按严重等级分组输出发现。"""
    if not findings:
        return

    sorted_findings = sorted(
        findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "INFO"), 99)
    )

    current_severity = None
    idx = 1
    for finding in sorted_findings:
        sev = finding.get("severity", "INFO")
        if sev != current_severity:
            current_severity = sev
            count = sum(1 for f2 in sorted_findings if f2.get("severity") == sev)
            print(f"\n**{SEVERITY_LABELS.get(sev, sev)}** ({count}项)")

        title = finding.get("title", "")
        analyzer = finding.get("analyzer", "")
        file_path = finding.get("file_path") or ""
        line = finding.get("line_number") or ""
        snippet = finding.get("snippet") or ""
        desc = finding.get("description", "")

        if file_path:
            location = f" ({analyzer}, {file_path}"
            if line:
                location += f":{line}"
            location += ")"
        else:
            location = f" ({analyzer})"

        print(f"{idx}. **{title}**{location}")
        if snippet:
            print(f"   - `{snippet}`")
        print(f"   - {desc}")
        idx += 1


def process_csv(csv_path: str) -> None:
    """读取 CSV 并输出格式化摘要。"""
    with open(csv_path, "r", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    record_count = len(rows)

    if record_count > 11:
        print(f"TOO_MANY_RECORDS|{record_count}|{csv_path}")
        return

    for row in rows:
        skill_name = row.get("skill_name", "")
        skill_path = row.get("skill_path", "")
        is_safe = row.get("is_safe", "True")
        max_severity = row.get("max_severity", "")
        findings_count = row.get("findings_count", "0")
        risk_level = row.get("risk_level", "")
        skill_verdict = row.get("skill_verdict", "")
        verdict_reasoning = row.get("verdict_reasoning", "")
        llm_assessment = row.get("llm_overall_assessment", "")

        has_meta = bool(risk_level and skill_verdict)

        if has_meta:
            verdict_level = VERDICT_ORDER.get(skill_verdict, 0)
            risk_level_val = RISK_ORDER.get(risk_level, 0)
            conclusion = (
                "不安全"
                if verdict_level >= 1 and risk_level_val >= 3
                else "安全"
            )
            print("=== 安全扫描结果 ===")
            print(f"Skill: {skill_name}")
            print(f"文件位置: {skill_path}")
            print(f"结论: {conclusion} ({skill_verdict} + {risk_level})")
            print(f"最高严重等级: {max_severity}")
            print(f"发现问题数: {findings_count}")
            print(f"风险等级: {risk_level}")
            print(f"评估说明: {llm_assessment or verdict_reasoning}")
        else:
            conclusion = "安全" if is_safe == "True" else "不安全"
            print("=== 安全扫描结果 ===")
            print(f"Skill: {skill_name}")
            print(f"文件位置: {skill_path}")
            print(f"结论: {conclusion}")
            print(f"最高严重等级: {max_severity}")
            print(f"发现问题数: {findings_count}")
            print(f"评估说明: {llm_assessment}")

        # 提取并格式化 findings
        full_json = row.get("full_json", "")
        if full_json:
            data = json.loads(full_json)
            findings = data.get("findings", [])
            format_findings(findings)

        print(f"\n完整结果已保存到: {csv_path}")


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python parse_scan_result.py <csv_file>", file=sys.stderr)
        sys.exit(1)

    process_csv(sys.argv[1])


if __name__ == "__main__":
    main()
