"""
Unified threat intelligence analyzer.

Aggregates results from multiple threat intel backends for both:
- Phase A: Binary file hash lookups
- Phase B: IOC extraction from md/script files + multi-source queries
"""

from __future__ import annotations

import logging
from pathlib import Path

from ...models import Finding, Severity, Skill, ThreatCategory
from ..base import BaseAnalyzer
from .base import (
    IOCIntelResult,
    IOCItem,
    ThreatIntelBackend,
    ThreatIntelResult,
    calculate_sha256,
    is_binary_file,
)
from .ioc_extractor import IOCExtractor

logger = logging.getLogger(__name__)


class ThreatIntelAnalyzer(BaseAnalyzer):
    """Analyzer that queries multiple threat intel sources.

    Phase A: Scans binary files via hash lookups across all backends.
    Phase B: Extracts IOCs (URLs, domains, IPs, hashes) from markdown
             and script files, then queries backends for threat intelligence.
    """

    def __init__(
        self,
        backends: list[ThreatIntelBackend],
        upload_files: bool = False,
        extract_iocs: bool = True,
    ):
        super().__init__("threat_intel_analyzer")
        self.backends = backends
        self.upload_files = upload_files
        self.extract_iocs = extract_iocs
        self.validated_binary_files: list[str] = []
        self._ioc_extractor = IOCExtractor()

    def analyze(self, skill: Skill) -> list[Finding]:
        findings: list[Finding] = []

        # Phase A: Binary file hash lookups
        binary_findings, validated = self._analyze_binary_files(skill)
        findings.extend(binary_findings)
        self.validated_binary_files = validated

        # Phase B: IOC extraction + queries
        if self.extract_iocs:
            ioc_findings = self._analyze_iocs(skill)
            findings.extend(ioc_findings)

        return findings

    # ------------------------------------------------------------------
    # Phase A: Binary file hash lookups
    # ------------------------------------------------------------------

    def _analyze_binary_files(self, skill: Skill) -> tuple[list[Finding], list[str]]:
        """Query all backends for binary file hashes."""
        findings: list[Finding] = []
        validated_files: list[str] = []
        binary_files = [f for f in skill.files if is_binary_file(f.relative_path)]

        for skill_file in binary_files:
            try:
                file_path = Path(skill.directory) / skill_file.relative_path
                file_hash = calculate_sha256(file_path)
            except OSError as e:
                logger.warning("Cannot read file %s: %s", skill_file.relative_path, e)
                continue

            logger.info("Checking file: %s (SHA256: %s)", skill_file.relative_path, file_hash)

            source_results: dict[str, ThreatIntelResult] = {}
            needs_upload = True

            for backend in self.backends:
                if not backend.supports_hash_lookup:
                    continue
                result = backend.query_hash(file_hash)
                if result is not None:
                    source_results[backend.name] = result
                    needs_upload = False

            # If no backend found the hash and upload is enabled, try uploading
            if not source_results and self.upload_files:
                for backend in self.backends:
                    if backend.supports_file_submission:
                        result = backend.submit_file(file_path, file_hash)
                        if result is not None:
                            source_results[backend.name] = result
                            break

            if not source_results:
                if not needs_upload:
                    logger.info("Hash not found in any backend: %s", skill_file.relative_path)
                continue

            # Aggregate results
            is_malicious = any(
                r.malicious > 0 or r.suspicious > 0 for r in source_results.values()
            )
            if is_malicious:
                findings.append(self._create_file_finding(skill_file, file_hash, source_results))
            else:
                logger.info("File validated as safe: %s", skill_file.relative_path)
                validated_files.append(skill_file.relative_path)

        return findings, validated_files

    def _create_file_finding(
        self,
        skill_file,
        file_hash: str,
        source_results: dict[str, ThreatIntelResult],
    ) -> Finding:
        """Create a finding for a malicious binary file."""
        # Aggregate severity across sources
        severity = self._aggregate_file_severity(source_results)
        # Build description from all sources
        descriptions = []
        for name, r in source_results.items():
            if r.malicious > 0 or r.suspicious > 0:
                descriptions.append(f"{name}: {r.malicious} malicious, {r.suspicious} suspicious / {r.total} total")

        source_meta = {
            name: {
                "malicious": r.malicious,
                "suspicious": r.suspicious,
                "total": r.total,
                "verdict": r.verdict,
                "permalink": r.permalink,
            }
            for name, r in source_results.items()
        }
        references = [r.permalink for r in source_results.values() if r.permalink]

        return Finding(
            id=f"TI_{file_hash[:8]}",
            rule_id="THREAT_INTEL_MALICIOUS_FILE",
            category=ThreatCategory.MALWARE,
            severity=severity,
            title=f"Malicious file detected: {skill_file.relative_path}",
            description=(
                f"Threat intelligence detected this file as malicious. "
                f"{'; '.join(descriptions)}. SHA256: {file_hash}"
            ),
            file_path=skill_file.relative_path,
            line_number=None,
            snippet=f"File hash: {file_hash}",
            remediation="Remove this file from the skill package.",
            analyzer="threat_intel",
            metadata={
                "confidence": self._compute_confidence(source_results),
                "file_hash": file_hash,
                "sources": source_meta,
                "references": references,
            },
        )

    @staticmethod
    def _aggregate_file_severity(results: dict[str, ThreatIntelResult]) -> Severity:
        """Determine severity from multi-source file hash results."""
        max_ratio = 0.0
        source_count_with_hits = 0
        for r in results.values():
            if r.total > 0:
                ratio = r.malicious / r.total
                max_ratio = max(max_ratio, ratio)
            if r.malicious > 0:
                source_count_with_hits += 1

        # Multi-source corroboration boosts severity
        if source_count_with_hits >= 3 and max_ratio >= 0.1:
            return Severity.CRITICAL
        if max_ratio >= 0.3:
            return Severity.CRITICAL
        if max_ratio >= 0.1:
            return Severity.HIGH
        if source_count_with_hits >= 2:
            return Severity.HIGH
        return Severity.MEDIUM

    @staticmethod
    def _compute_confidence(results: dict[str, ThreatIntelResult]) -> float:
        """Compute confidence based on number of sources and detection ratio."""
        sources_with_hits = sum(1 for r in results.values() if r.malicious > 0)
        total_sources = len(results)
        if total_sources == 0:
            return 0.5
        base = 0.7 if sources_with_hits >= 2 else 0.6
        # Boost if multiple sources agree
        if sources_with_hits == total_sources:
            base = min(base + 0.15, 0.99)
        return base

    # ------------------------------------------------------------------
    # Phase B: IOC extraction + multi-source queries
    # ------------------------------------------------------------------

    def _analyze_iocs(self, skill: Skill) -> list[Finding]:
        """Extract IOCs from text files and query threat intel backends."""
        findings: list[Finding] = []

        # Collect IOCs from markdown and script files
        target_files = skill.get_markdown_files() + skill.get_scripts()
        all_iocs: list[IOCItem] = []
        for f in target_files:
            content = f.read_content()
            if content:
                iocs = self._ioc_extractor.extract(content, f.relative_path)
                all_iocs.extend(iocs)

        if not all_iocs:
            return findings

        # Deduplicate across files
        seen: set[tuple[str, str]] = set()
        unique_iocs: list[IOCItem] = []
        for ioc in all_iocs:
            key = (ioc.type, ioc.value)
            if key not in seen:
                seen.add(key)
                unique_iocs.append(ioc)

        logger.info("Extracted %d unique IOCs from %d files", len(unique_iocs), len(target_files))

        # Query each IOC against all compatible backends
        for ioc in unique_iocs:
            source_results: dict[str, IOCIntelResult] = {}
            for backend in self.backends:
                if ioc.type in backend.supported_ioc_types:
                    try:
                        result = backend.query_ioc(ioc.type, ioc.value)
                        if result is not None:
                            source_results[backend.name] = result
                    except Exception as e:
                        logger.warning(
                            "IOC query failed on %s for %s %s: %s",
                            backend.name, ioc.type, ioc.value, e,
                        )

            # Only create finding if at least one source reports a threat
            if any(r.threat_level in ("high", "medium") for r in source_results.values()):
                findings.append(self._create_ioc_finding(ioc, source_results))

        return findings

    def _create_ioc_finding(
        self,
        ioc: IOCItem,
        source_results: dict[str, IOCIntelResult],
    ) -> Finding:
        """Create a finding for a malicious IOC."""
        severity = self._aggregate_ioc_severity(source_results)
        category = self._map_ioc_category(ioc.type)

        descriptions = []
        for name, r in source_results.items():
            tag_str = f" (tags: {', '.join(r.tags)})" if r.tags else ""
            descriptions.append(f"{name}: {r.threat_level}{tag_str}")

        source_meta = {
            name: {
                "threat_level": r.threat_level,
                "tags": list(r.tags),
                "permalink": r.permalink,
            }
            for name, r in source_results.items()
        }
        references = [r.permalink for r in source_results.values() if r.permalink]

        return Finding(
            id=f"TI_IOC_{ioc.type}_{hash(ioc.value) & 0xFFFFFFFF:08x}",
            rule_id="THREAT_INTEL_MALICIOUS_IOC",
            category=category,
            severity=severity,
            title=f"Malicious {ioc.type} detected: {ioc.value}",
            description=(
                f"Malicious {ioc.type} found in {ioc.source_file}:{ioc.source_line}. "
                f"{'; '.join(descriptions)}"
            ),
            file_path=ioc.source_file,
            line_number=ioc.source_line,
            snippet=ioc.value,
            remediation=f"Review and remove the suspicious {ioc.type} from the skill.",
            analyzer="threat_intel",
            metadata={
                "ioc_type": ioc.type,
                "ioc_value": ioc.value,
                "sources": source_meta,
                "references": references,
            },
        )

    @staticmethod
    def _aggregate_ioc_severity(results: dict[str, IOCIntelResult]) -> Severity:
        """Determine severity from multi-source IOC results."""
        high_count = sum(1 for r in results.values() if r.threat_level == "high")
        medium_count = sum(1 for r in results.values() if r.threat_level == "medium")

        if high_count >= 2:
            return Severity.CRITICAL
        if high_count >= 1:
            return Severity.HIGH
        if medium_count >= 2:
            return Severity.HIGH
        if medium_count >= 1:
            return Severity.MEDIUM
        return Severity.LOW

    @staticmethod
    def _map_ioc_category(ioc_type: str) -> ThreatCategory:
        """Map IOC type to threat category."""
        mapping: dict[str, ThreatCategory] = {
            "url": ThreatCategory.SUPPLY_CHAIN_ATTACK,
            "domain": ThreatCategory.SUPPLY_CHAIN_ATTACK,
            "ip": ThreatCategory.COMMAND_INJECTION,
            "hash": ThreatCategory.MALWARE,
        }
        return mapping.get(ioc_type, ThreatCategory.POLICY_VIOLATION)
