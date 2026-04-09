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

"""
CSV format reporter for scan results.

Produces one row per skill with summary-level fields.
"""

import csv
import io
import json

from ..models import Report, ScanResult

FIELDS = (
    "skill_name",
    "skill_path",
    "is_safe",
    "max_severity",
    "findings_count",
    "scan_duration_seconds",
    "analyzers_used",
    "llm_overall_assessment",
    "timestamp",
    "risk_level",
    "skill_verdict",
    "verdict_reasoning",
    "full_json",
)


def _row_from_result(d: dict) -> dict:
    """Flatten a ScanResult dict into a flat row for CSV output."""
    analyzers = d.get("analyzers_used", [])
    if isinstance(analyzers, list):
        analyzers = ";".join(analyzers)
    scan_metadata = d.get("scan_metadata") or {}
    meta_ra = scan_metadata.get("meta_risk_assessment") or {}
    return {
        "skill_name": d.get("skill_name", ""),
        "skill_path": d.get("skill_path", ""),
        "is_safe": d.get("is_safe", ""),
        "max_severity": d.get("max_severity", ""),
        "findings_count": d.get("findings_count", 0),
        "scan_duration_seconds": d.get("scan_duration_seconds", 0.0),
        "analyzers_used": analyzers,
        "llm_overall_assessment": scan_metadata.get("llm_overall_assessment", ""),
        "timestamp": d.get("timestamp", ""),
        "risk_level": meta_ra.get("risk_level", ""),
        "skill_verdict": meta_ra.get("skill_verdict", ""),
        "verdict_reasoning": meta_ra.get("verdict_reasoning", ""),
        "full_json": json.dumps(d, ensure_ascii=False, indent=2, sort_keys=True, default=str),
    }


class CSVReporter:
    """Generates CSV format reports.

    For a single *ScanResult* the CSV contains one data row.
    For a *Report* (from ``scan-all``) each skill gets its own row.
    """

    def generate_report(self, data: ScanResult | Report) -> str:
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=FIELDS, lineterminator="\n")
        writer.writeheader()

        if isinstance(data, Report):
            for result in data.scan_results:
                writer.writerow(_row_from_result(result.to_dict()))
        else:
            writer.writerow(_row_from_result(data.to_dict()))

        return buf.getvalue()

    def save_report(self, data: ScanResult | Report, output_path: str) -> None:
        csv_text = self.generate_report(data)
        with open(output_path, "w", encoding="utf-8", newline="") as f:
            f.write(csv_text)
