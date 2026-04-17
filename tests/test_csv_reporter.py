"""Tests for csv_reporter.py: CSVReporter."""

import csv
import io
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from skill_scanner.core.models import Finding, Report, ScanResult, Severity, ThreatCategory
from skill_scanner.core.reporters.csv_reporter import CSVReporter, FIELDS, _row_from_result


def _make_scan_result(
    skill_name: str = "test-skill",
    findings: list[Finding] | None = None,
    analyzers: list[str] | None = None,
    scan_metadata: dict | None = None,
) -> ScanResult:
    """Helper to create a ScanResult for testing."""
    return ScanResult(
        skill_name=skill_name,
        skill_directory=f"/skills/{skill_name}",
        findings=findings or [],
        analyzers_used=analyzers or ["static"],
        scan_duration_seconds=0.1,
        scan_metadata=scan_metadata or {},
    )


# ---------------------------------------------------------------------------
# _row_from_result
# ---------------------------------------------------------------------------

class TestRowFromResult:
    def test_basic_fields(self):
        sr = _make_scan_result(skill_name="my-skill")
        d = sr.to_dict()
        row = _row_from_result(d)
        assert row["skill_name"] == "my-skill"
        assert row["is_safe"] is True
        assert row["findings_count"] == 0

    def test_analyzers_joined(self):
        sr = _make_scan_result(analyzers=["static", "behavioral"])
        row = _row_from_result(sr.to_dict())
        assert "static;behavioral" == row["analyzers_used"]

    def test_meta_risk_assessment_fields(self):
        meta = {
            "meta_risk_assessment": {
                "risk_level": "HIGH",
                "skill_verdict": "unsafe",
                "verdict_reasoning": "Multiple injection patterns",
            }
        }
        sr = _make_scan_result(scan_metadata=meta)
        row = _row_from_result(sr.to_dict())
        assert row["risk_level"] == "HIGH"
        assert row["skill_verdict"] == "unsafe"
        assert "Multiple injection" in row["verdict_reasoning"]

    def test_full_json_field(self):
        sr = _make_scan_result()
        row = _row_from_result(sr.to_dict())
        parsed = json.loads(row["full_json"])
        assert parsed["skill_name"] == "test-skill"

    def test_llm_overall_assessment(self):
        meta = {"llm_overall_assessment": "THREAT_DETECTED"}
        sr = _make_scan_result(scan_metadata=meta)
        row = _row_from_result(sr.to_dict())
        assert row["llm_overall_assessment"] == "THREAT_DETECTED"


# ---------------------------------------------------------------------------
# CSVReporter.generate_report
# ---------------------------------------------------------------------------

class TestCSVReporterGenerate:
    def test_single_scan_result(self):
        reporter = CSVReporter()
        sr = _make_scan_result()
        csv_text = reporter.generate_report(sr)
        reader = csv.DictReader(io.StringIO(csv_text))
        rows = list(reader)
        assert len(rows) == 1
        assert rows[0]["skill_name"] == "test-skill"

    def test_report_with_multiple_results(self):
        reporter = CSVReporter()
        results = [
            _make_scan_result(skill_name="skill-a"),
            _make_scan_result(skill_name="skill-b"),
        ]
        report = Report(scan_results=results)
        csv_text = reporter.generate_report(report)
        reader = csv.DictReader(io.StringIO(csv_text))
        rows = list(reader)
        assert len(rows) == 2
        assert rows[0]["skill_name"] == "skill-a"
        assert rows[1]["skill_name"] == "skill-b"

    def test_all_fields_present(self):
        reporter = CSVReporter()
        sr = _make_scan_result()
        csv_text = reporter.generate_report(sr)
        reader = csv.DictReader(io.StringIO(csv_text))
        rows = list(reader)
        assert set(rows[0].keys()) == set(FIELDS)

    def test_findings_with_data(self):
        finding = Finding(
            id="f1",
            rule_id="RULE_001",
            category=ThreatCategory.PROMPT_INJECTION,
            severity=Severity.HIGH,
            title="Injection",
            description="test",
        )
        sr = _make_scan_result(findings=[finding])
        reporter = CSVReporter()
        csv_text = reporter.generate_report(sr)
        reader = csv.DictReader(io.StringIO(csv_text))
        rows = list(reader)
        assert rows[0]["is_safe"] == "False"
        assert rows[0]["findings_count"] == "1"


# ---------------------------------------------------------------------------
# CSVReporter.save_report
# ---------------------------------------------------------------------------

class TestCSVReporterSave:
    def test_saves_to_file(self, tmp_path: Path):
        reporter = CSVReporter()
        sr = _make_scan_result()
        out = tmp_path / "report.csv"
        reporter.save_report(sr, str(out))
        assert out.exists()
        content = out.read_text(encoding="utf-8")
        assert "test-skill" in content