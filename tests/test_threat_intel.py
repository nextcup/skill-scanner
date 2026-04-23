"""
Tests for the unified threat intelligence analyzer and backends.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from skill_scanner.core.analyzers.threat_intel.base import (
    IOCIntelResult,
    IOCItem,
    ThreatIntelResult,
    calculate_sha256,
    is_binary_file,
    is_private_ip,
)
from skill_scanner.core.analyzers.threat_intel.ioc_extractor import IOCExtractor
from skill_scanner.core.analyzers.threat_intel.threat_intel_analyzer import (
    ThreatIntelAnalyzer,
)
from skill_scanner.core.models import Finding, Severity, Skill, SkillFile, SkillManifest, ThreatCategory


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_skill(tmp_path: Path, files: dict[str, str]) -> Skill:
    """Create a Skill with given files."""
    manifest = SkillManifest(name="test-skill", description="Test skill")
    skill_files: list[SkillFile] = []
    for rel_path, content in files.items():
        fpath = tmp_path / rel_path
        fpath.parent.mkdir(parents=True, exist_ok=True)
        fpath.write_text(content, encoding="utf-8")
        ext = fpath.suffix.lower()
        if ext in (".md",):
            ftype = "markdown"
        elif ext in (".py", ".sh", ".js"):
            ftype = ext.lstrip(".")
        else:
            ftype = "other"
        skill_files.append(SkillFile(path=fpath, relative_path=rel_path, file_type=ftype))

    return Skill(
        directory=tmp_path,
        manifest=manifest,
        skill_md_path=tmp_path / "SKILL.md",
        instruction_body="Test",
        files=skill_files,
    )


# ---------------------------------------------------------------------------
# Tests: base.py utilities
# ---------------------------------------------------------------------------

class TestBaseUtils:
    def test_is_binary_file_png(self):
        assert is_binary_file("image.png") is True

    def test_is_binary_file_exe(self):
        assert is_binary_file("program.exe") is True

    def test_is_binary_file_pdf(self):
        assert is_binary_file("doc.pdf") is True

    def test_is_binary_file_py(self):
        assert is_binary_file("script.py") is False

    def test_is_binary_file_md(self):
        assert is_binary_file("README.md") is False

    def test_is_binary_file_unknown(self):
        assert is_binary_file("data.xyz") is False

    def test_is_private_ip(self):
        assert is_private_ip("127.0.0.1") is True
        assert is_private_ip("192.168.1.1") is True
        assert is_private_ip("10.0.0.1") is True
        assert is_private_ip("172.16.0.1") is True
        assert is_private_ip("8.8.8.8") is False
        assert is_private_ip("1.1.1.1") is False

    def test_calculate_sha256(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("hello world")
        h = calculate_sha256(f)
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)


# ---------------------------------------------------------------------------
# Tests: IOC extractor
# ---------------------------------------------------------------------------

class TestIOCExtractor:
    def setup_method(self):
        self.extractor = IOCExtractor()

    def test_extract_url(self):
        content = "Check out https://malware-c2.evil.net/payload for details"
        iocs = self.extractor.extract(content, "test.md")
        urls = [i for i in iocs if i.type == "url"]
        assert len(urls) >= 1
        assert any("malware-c2.evil.net" in u.value for u in urls)

    def test_extract_url_skips_localhost(self):
        content = "Connect to http://localhost:8080/api"
        iocs = self.extractor.extract(content, "test.py")
        urls = [i for i in iocs if i.type == "url"]
        assert len(urls) == 0

    def test_extract_url_skips_example_com(self):
        content = "See https://example.com/docs for info"
        iocs = self.extractor.extract(content, "test.md")
        urls = [i for i in iocs if i.type == "url"]
        assert len(urls) == 0

    def test_extract_ip(self):
        content = "Connect to 8.8.8.8 for DNS"
        iocs = self.extractor.extract(content, "test.py")
        ips = [i for i in iocs if i.type == "ip"]
        assert len(ips) >= 1
        assert ips[0].value == "8.8.8.8"

    def test_extract_ip_skips_private(self):
        content = "Server at 192.168.1.100"
        iocs = self.extractor.extract(content, "test.py")
        ips = [i for i in iocs if i.type == "ip"]
        assert len(ips) == 0

    def test_extract_domain(self):
        content = "Download from malware-c2.evil.net"
        iocs = self.extractor.extract(content, "test.md")
        domains = [i for i in iocs if i.type == "domain"]
        assert any("malware-c2.evil.net" in d.value for d in domains)

    def test_extract_domain_skips_trusted(self):
        content = "Install from github.com/user/repo"
        iocs = self.extractor.extract(content, "test.md")
        domains = [i for i in iocs if i.type == "domain"]
        assert not any("github.com" == d.value for d in domains)

    def test_extract_domain_skips_code_patterns(self):
        content = "os.path.exists('/tmp/test')"
        iocs = self.extractor.extract(content, "test.py")
        domains = [i for i in iocs if i.type == "domain"]
        # "os.path" should not be treated as a domain
        assert not any("os.path" in d.value for d in domains)

    def test_extract_sha256_hash(self):
        h = "a" * 64  # 64-char hex string
        content = f"File hash: {h}"
        iocs = self.extractor.extract(content, "test.py")
        hashes = [i for i in iocs if i.type == "hash"]
        assert len(hashes) >= 1
        assert hashes[0].value == h

    def test_extract_md5_hash(self):
        h = "a" * 32
        content = f"MD5: {h}"
        iocs = self.extractor.extract(content, "test.py")
        hashes = [i for i in iocs if i.type == "hash"]
        assert len(hashes) >= 1

    def test_deduplication(self):
        content = "URL: https://malware-c2.evil.net/a\nAgain: https://malware-c2.evil.net/a"
        iocs = self.extractor.extract(content, "test.md")
        urls = [i for i in iocs if i.type == "url"]
        assert len(urls) == 1

    def test_source_line_tracking(self):
        content = "Line 1\nhttps://malware-c2.evil.net/payload\nLine 3"
        iocs = self.extractor.extract(content, "test.md")
        urls = [i for i in iocs if i.type == "url"]
        assert urls[0].source_line == 2


# ---------------------------------------------------------------------------
# Tests: ThreatIntelAnalyzer (with mock backends)
# ---------------------------------------------------------------------------

class MockBackend:
    """Mock threat intel backend for testing."""

    def __init__(
        self,
        name: str = "mock",
        hash_result: ThreatIntelResult | None = None,
        ioc_result: IOCIntelResult | None = None,
    ):
        self.name = name
        self.supports_hash_lookup = True
        self.supports_file_submission = False
        self.supported_ioc_types = ["url", "domain", "ip", "hash"]
        self._hash_result = hash_result
        self._ioc_result = ioc_result

    def query_hash(self, file_hash: str) -> ThreatIntelResult | None:
        return self._hash_result

    def submit_file(self, file_path: Path, file_hash: str) -> ThreatIntelResult | None:
        return None

    def query_ioc(self, ioc_type: str, ioc_value: str) -> IOCIntelResult | None:
        return self._ioc_result


class TestThreatIntelAnalyzer:
    def test_no_binary_files(self, tmp_path):
        """Should return empty findings when no binary files exist."""
        skill = _make_skill(tmp_path, {"SKILL.md": "# Test", "main.py": "print('hello')"})
        backend = MockBackend()
        analyzer = ThreatIntelAnalyzer(backends=[backend], extract_iocs=False)
        findings = analyzer.analyze(skill)
        assert findings == []

    def test_malicious_binary_file(self, tmp_path):
        """Should create finding for a file flagged as malicious."""
        # Create a dummy binary file
        bin_path = tmp_path / "payload.exe"
        bin_path.write_bytes(b"\x00" * 100)
        skill = Skill(
            directory=tmp_path,
            manifest=SkillManifest(name="test", description="test"),
            skill_md_path=tmp_path / "SKILL.md",
            instruction_body="test",
            files=[SkillFile(path=bin_path, relative_path="payload.exe", file_type="other")],
        )
        backend = MockBackend(
            hash_result=ThreatIntelResult(
                source="mock", malicious=10, total=20, file_hash="abc",
            ),
        )
        analyzer = ThreatIntelAnalyzer(backends=[backend], extract_iocs=False)
        findings = analyzer.analyze(skill)
        assert len(findings) == 1
        assert findings[0].rule_id == "THREAT_INTEL_MALICIOUS_FILE"
        assert findings[0].severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)

    def test_safe_binary_file_validated(self, tmp_path):
        """Safe files should be tracked in validated_binary_files."""
        bin_path = tmp_path / "safe.png"
        bin_path.write_bytes(b"\x89PNG\r\n" + b"\x00" * 100)
        skill = Skill(
            directory=tmp_path,
            manifest=SkillManifest(name="test", description="test"),
            skill_md_path=tmp_path / "SKILL.md",
            instruction_body="test",
            files=[SkillFile(path=bin_path, relative_path="safe.png", file_type="other")],
        )
        backend = MockBackend(
            hash_result=ThreatIntelResult(
                source="mock", malicious=0, total=20, verdict="clean",
            ),
        )
        analyzer = ThreatIntelAnalyzer(backends=[backend], extract_iocs=False)
        findings = analyzer.analyze(skill)
        assert len(findings) == 0
        assert "safe.png" in analyzer.validated_binary_files

    def test_ioc_extraction_with_malicious_ioc(self, tmp_path):
        """Should create finding when IOC is flagged as malicious."""
        skill = _make_skill(tmp_path, {
            "SKILL.md": "# Test\nConnect to https://evil-c2.com/beacon",
        })
        backend = MockBackend(
            ioc_result=IOCIntelResult(
                source="mock", ioc_type="domain", ioc_value="evil-c2.com",
                threat_level="high", tags=("c2", "apt"),
            ),
        )
        analyzer = ThreatIntelAnalyzer(backends=[backend], extract_iocs=True)
        # Disable binary file analysis (no binary files)
        findings = analyzer.analyze(skill)
        ioc_findings = [f for f in findings if f.rule_id == "THREAT_INTEL_MALICIOUS_IOC"]
        assert len(ioc_findings) >= 1
        assert ioc_findings[0].severity == Severity.HIGH

    def test_ioc_extraction_skips_safe_iocs(self, tmp_path):
        """Should not create finding when IOC is clean."""
        skill = _make_skill(tmp_path, {
            "SKILL.md": "# Test\nVisit https://github.com/repo",
        })
        backend = MockBackend(
            ioc_result=IOCIntelResult(
                source="mock", ioc_type="domain", ioc_value="github.com",
                threat_level="clean",
            ),
        )
        analyzer = ThreatIntelAnalyzer(backends=[backend], extract_iocs=True)
        findings = analyzer.analyze(skill)
        ioc_findings = [f for f in findings if f.rule_id == "THREAT_INTEL_MALICIOUS_IOC"]
        assert len(ioc_findings) == 0

    def test_multi_source_aggregation(self, tmp_path):
        """Multiple backends reporting should boost severity."""
        skill = _make_skill(tmp_path, {
            "SKILL.md": "# Test\nC2 server at https://malware.evil.com",
        })
        backend_a = MockBackend(
            name="backend_a",
            ioc_result=IOCIntelResult(
                source="backend_a", ioc_type="url", ioc_value="https://malware.evil.com",
                threat_level="high",
            ),
        )
        backend_b = MockBackend(
            name="backend_b",
            ioc_result=IOCIntelResult(
                source="backend_b", ioc_type="url", ioc_value="https://malware.evil.com",
                threat_level="high",
            ),
        )
        analyzer = ThreatIntelAnalyzer(backends=[backend_a, backend_b], extract_iocs=True)
        findings = analyzer.analyze(skill)
        ioc_findings = [f for f in findings if f.rule_id == "THREAT_INTEL_MALICIOUS_IOC"]
        assert len(ioc_findings) >= 1
        # 2 high sources → CRITICAL
        assert ioc_findings[0].severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# Tests: VirusTotal Backend
# ---------------------------------------------------------------------------

class TestVirusTotalBackend:
    def test_init(self):
        from skill_scanner.core.analyzers.threat_intel.virustotal_backend import VirusTotalBackend
        b = VirusTotalBackend(api_key="test-key")
        assert b.name == "virustotal"
        assert b.supports_hash_lookup is True
        assert b.supports_file_submission is True
        assert "url" in b.supported_ioc_types

    @patch("skill_scanner.core.analyzers.threat_intel.virustotal_backend.httpx.Client")
    def test_query_hash_malicious(self, mock_client_cls):
        from skill_scanner.core.analyzers.threat_intel.virustotal_backend import VirusTotalBackend
        mock_session = MagicMock()
        mock_client_cls.return_value = mock_session
        mock_session.get.return_value.status_code = 200
        mock_session.get.return_value.json.return_value = {
            "data": {"attributes": {
                "last_analysis_stats": {"malicious": 15, "suspicious": 3, "undetected": 50, "harmless": 5},
                "last_analysis_date": "2026-01-01",
            }},
        }
        b = VirusTotalBackend(api_key="test-key")
        result = b.query_hash("abc123")
        assert result is not None
        assert result.malicious == 15
        assert result.total == 73
        assert result.verdict == "malicious"

    @patch("skill_scanner.core.analyzers.threat_intel.virustotal_backend.httpx.Client")
    def test_query_hash_not_found(self, mock_client_cls):
        from skill_scanner.core.analyzers.threat_intel.virustotal_backend import VirusTotalBackend
        mock_session = MagicMock()
        mock_client_cls.return_value = mock_session
        mock_session.get.return_value.status_code = 404
        b = VirusTotalBackend(api_key="test-key")
        result = b.query_hash("abc123")
        assert result is None


# ---------------------------------------------------------------------------
# Tests: ThreatBook Backend
# ---------------------------------------------------------------------------

class TestThreatBookBackend:
    def test_init(self):
        from skill_scanner.core.analyzers.threat_intel.threatbook_backend import ThreatBookBackend
        b = ThreatBookBackend(api_key="test-key")
        assert b.name == "threatbook"
        assert b.supports_file_submission is False

    @patch("skill_scanner.core.analyzers.threat_intel.threatbook_backend.httpx.Client")
    def test_query_hash_malicious(self, mock_client_cls):
        from skill_scanner.core.analyzers.threat_intel.threatbook_backend import ThreatBookBackend
        mock_session = MagicMock()
        mock_client_cls.return_value = mock_session
        mock_session.get.return_value.status_code = 200
        mock_session.get.return_value.json.return_value = {
            "response_code": 0,
            "threat_level": "high",
            "verbose_msg": "Malicious",
        }
        b = ThreatBookBackend(api_key="test-key")
        result = b.query_hash("abc123")
        assert result is not None
        assert result.verdict == "malicious"


# ---------------------------------------------------------------------------
# Tests: Cuckoo Backend
# ---------------------------------------------------------------------------

class TestCuckooBackend:
    def test_init(self):
        from skill_scanner.core.analyzers.threat_intel.cuckoo_backend import CuckooBackend
        b = CuckooBackend(api_url="http://cuckoo:8090", api_key="token")
        assert b.name == "cuckoo"
        assert b.supports_file_submission is True
        assert "hash" in b.supported_ioc_types
        # Cuckoo doesn't support URL/domain/IP IOC queries
        assert "url" not in b.supported_ioc_types

    def test_submit_file_not_implemented_for_none_url(self):
        from skill_scanner.core.analyzers.threat_intel.cuckoo_backend import CuckooBackend
        b = CuckooBackend(api_url="http://cuckoo:8090")
        assert b.query_ioc("domain", "evil.com") is None


# ---------------------------------------------------------------------------
# Tests: Zftip Backend
# ---------------------------------------------------------------------------

class TestZftipBackend:
    def test_init(self):
        from skill_scanner.core.analyzers.threat_intel.zftip_backend import ZftipBackend
        b = ZftipBackend(api_url="http://20.20.136.105:50000", api_key="test-key")
        assert b.name == "zftip"
        assert b.supports_hash_lookup is False
        assert b.supports_file_submission is False
        assert "ip" in b.supported_ioc_types
        assert "domain" in b.supported_ioc_types
        assert "url" in b.supported_ioc_types

    def test_query_hash_returns_none(self):
        from skill_scanner.core.analyzers.threat_intel.zftip_backend import ZftipBackend
        b = ZftipBackend(api_url="http://localhost:50000", api_key="test-key")
        assert b.query_hash("abc123") is None

    def test_submit_file_returns_none(self, tmp_path):
        from skill_scanner.core.analyzers.threat_intel.zftip_backend import ZftipBackend
        b = ZftipBackend(api_url="http://localhost:50000", api_key="test-key")
        f = tmp_path / "test.txt"
        f.write_text("hello")
        assert b.submit_file(f, "abc") is None

    @patch("skill_scanner.core.analyzers.threat_intel.zftip_backend.httpx.Client")
    def test_query_ioc_malicious_domain(self, mock_client_cls):
        from skill_scanner.core.analyzers.threat_intel.zftip_backend import ZftipBackend
        mock_session = MagicMock()
        mock_client_cls.return_value = mock_session
        mock_session.post.return_value.status_code = 200
        mock_session.post.return_value.json.return_value = {
            "code": 200,
            "data": [
                {"xred.mooo.com": [{
                    "label": ["木马", "恶意软件", "远控后门"],
                    "credit_score": 80,
                    "category": 3,
                    "org": "Socketfire, Inc",
                    "name": "xred.mooo.com",
                    "dns_parsing_records": [{"value": "101.86.170.36", "key": "A"}],
                }]},
            ],
        }
        b = ZftipBackend(api_url="http://localhost:50000", api_key="test-key")
        result = b.query_ioc("domain", "xred.mooo.com")
        assert result is not None
        assert result.source == "zftip"
        assert result.ioc_value == "xred.mooo.com"
        assert result.threat_level == "high"
        assert "木马" in result.tags
        assert result.details["credit_score"] == 80

    @patch("skill_scanner.core.analyzers.threat_intel.zftip_backend.httpx.Client")
    def test_query_ioc_empty_result(self, mock_client_cls):
        from skill_scanner.core.analyzers.threat_intel.zftip_backend import ZftipBackend
        mock_session = MagicMock()
        mock_client_cls.return_value = mock_session
        mock_session.post.return_value.status_code = 200
        mock_session.post.return_value.json.return_value = {
            "code": 200,
            "data": [{"54.91.154.110": []}],
        }
        b = ZftipBackend(api_url="http://localhost:50000", api_key="test-key")
        result = b.query_ioc("ip", "54.91.154.110")
        assert result is None

    @patch("skill_scanner.core.analyzers.threat_intel.zftip_backend.httpx.Client")
    def test_query_ioc_non_200_code(self, mock_client_cls):
        from skill_scanner.core.analyzers.threat_intel.zftip_backend import ZftipBackend
        mock_session = MagicMock()
        mock_client_cls.return_value = mock_session
        mock_session.post.return_value.status_code = 200
        mock_session.post.return_value.json.return_value = {"code": 500, "data": []}
        b = ZftipBackend(api_url="http://localhost:50000", api_key="test-key")
        result = b.query_ioc("ip", "1.2.3.4")
        assert result is None

    @patch("skill_scanner.core.analyzers.threat_intel.zftip_backend.httpx.Client")
    def test_query_ioc_unsupported_type(self, mock_client_cls):
        from skill_scanner.core.analyzers.threat_intel.zftip_backend import ZftipBackend
        b = ZftipBackend(api_url="http://localhost:50000", api_key="test-key")
        result = b.query_ioc("hash", "abc123")
        assert result is None
        mock_session = mock_client_cls.return_value
        mock_session.post.assert_not_called()

    @pytest.mark.integration
    def test_query_ioc_live(self):
        """Live Zftip API test — query xred.mooo.com.

        Requires ZFTIP_URL and ZFTIP_API_KEY in environment or .env file.
        """
        import os

        url = os.getenv("ZFTIP_URL")
        key = os.getenv("ZFTIP_API_KEY")
        if not url or not key:
            pytest.skip("ZFTIP_URL/ZFTIP_API_KEY not set, skipping live test")

        from skill_scanner.core.analyzers.threat_intel.zftip_backend import ZftipBackend

        b = ZftipBackend(api_url=url, api_key=key, timeout=30)
        result = b.query_ioc("domain", "xred.mooo.com")
        assert result is not None
        assert result.source == "zftip"
        assert result.ioc_value == "xred.mooo.com"
        assert result.threat_level in ("high", "medium", "low", "info", "clean")
        print(f"\n[Zftip] xred.mooo.com → threat_level={result.threat_level}, "
              f"tags={result.tags}, credit_score={result.details.get('credit_score')}")

    @pytest.mark.integration
    def test_query_ip_live(self):
        """Live Zftip API test — query 54.91.154.110 (should return empty).

        Requires ZFTIP_URL and ZFTIP_API_KEY in environment or .env file.
        """
        import os

        url = os.getenv("ZFTIP_URL")
        key = os.getenv("ZFTIP_API_KEY")
        if not url or not key:
            pytest.skip("ZFTIP_URL/ZFTIP_API_KEY not set, skipping live test")

        from skill_scanner.core.analyzers.threat_intel.zftip_backend import ZftipBackend

        b = ZftipBackend(api_url=url, api_key=key, timeout=30)
        result = b.query_ioc("ip", "54.91.154.110")
        print(f"\n[Zftip] 54.91.154.110 → {result}")


# ---------------------------------------------------------------------------
# Tests: OTX Backend
# ---------------------------------------------------------------------------

class TestOTXBackend:
    def test_init(self):
        from skill_scanner.core.analyzers.threat_intel.otx_backend import OTXBackend
        b = OTXBackend(api_key="test-key")
        assert b.name == "otx"
        assert b.supports_hash_lookup is True
        assert b.supports_file_submission is False
        assert len(b.supported_ioc_types) == 4

    @patch("skill_scanner.core.analyzers.threat_intel.otx_backend.httpx.Client")
    def test_query_hash_with_pulses(self, mock_client_cls):
        from skill_scanner.core.analyzers.threat_intel.otx_backend import OTXBackend
        mock_session = MagicMock()
        mock_client_cls.return_value = mock_session
        mock_session.get.return_value.status_code = 200
        mock_session.get.return_value.json.return_value = {
            "pulse_info": {
                "count": 3,
                "pulses": [
                    {"name": "APT28 Campaign", "tags": ["apt", "russia"]},
                    {"name": "Sofacy", "tags": ["malware"]},
                ],
            },
            "general": {"av_classification": {}},
        }
        b = OTXBackend(api_key="test-key")
        result = b.query_hash("abc123")
        assert result is not None
        assert result.malicious == 1
        assert result.verdict == "malicious"
        assert len(result.details["pulse_names"]) == 2

    @pytest.mark.integration
    def test_query_ip_live(self):
        """Live OTX API test — query IP 54.91.154.110.

        Requires OTX_API_KEY in environment or .env file.
        Skip if key not available.
        """
        import os

        key = os.getenv("OTX_API_KEY")
        if not key:
            pytest.skip("OTX_API_KEY not set, skipping live test")

        from skill_scanner.core.analyzers.threat_intel.otx_backend import OTXBackend

        b = OTXBackend(api_key=key, timeout=30)
        result = b.query_ioc("ip", "54.91.154.110")
        assert result is not None
        assert result.source == "otx"
        assert result.ioc_type == "ip"
        assert result.ioc_value == "54.91.154.110"
        assert result.threat_level in ("high", "medium", "low", "info", "clean")
        assert result.permalink is not None
        print(f"\n[OTX] IP 54.91.154.110 → threat_level={result.threat_level}, "
              f"tags={result.tags}, pulse_count={result.details.get('pulse_count')}")

    @pytest.mark.integration
    def test_query_hash_live(self):
        """Live OTX API test — query a known file hash.

        Uses EICAR test file hash. Requires OTX_API_KEY.
        """
        import os

        key = os.getenv("OTX_API_KEY")
        if not key:
            pytest.skip("OTX_API_KEY not set, skipping live test")

        from skill_scanner.core.analyzers.threat_intel.otx_backend import OTXBackend

        # EICAR SHA256
        eicar_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        b = OTXBackend(api_key=key, timeout=30)
        result = b.query_hash(eicar_hash)
        assert result is not None
        assert result.source == "otx"
        assert result.file_hash == eicar_hash
        print(f"\n[OTX] EICAR hash → malicious={result.malicious}, "
              f"verdict={result.verdict}, pulses={result.details.get('pulse_count')}")

    @pytest.mark.integration
    def test_query_domain_live(self):
        """Live OTX API test — query a domain.

        Requires OTX_API_KEY.
        """
        import os

        key = os.getenv("OTX_API_KEY")
        if not key:
            pytest.skip("OTX_API_KEY not set, skipping live test")

        from skill_scanner.core.analyzers.threat_intel.otx_backend import OTXBackend

        b = OTXBackend(api_key=key, timeout=30)
        result = b.query_ioc("domain", "polymarket.com")
        assert result is not None
        assert result.source == "otx"
        assert result.ioc_type == "domain"
        print(f"\n[OTX] polymarket.com → threat_level={result.threat_level}, "
              f"tags={result.tags}, pulse_count={result.details.get('pulse_count')}")


# ---------------------------------------------------------------------------
# Tests: Severity aggregation
# ---------------------------------------------------------------------------

class TestSeverityAggregation:
    def test_high_ratio_is_critical(self):
        results = {
            "vt": ThreatIntelResult(source="vt", malicious=30, total=50),
        }
        assert ThreatIntelAnalyzer._aggregate_file_severity(results) == Severity.CRITICAL

    def test_medium_ratio_is_high(self):
        results = {
            "vt": ThreatIntelResult(source="vt", malicious=8, total=50),
        }
        assert ThreatIntelAnalyzer._aggregate_file_severity(results) == Severity.HIGH

    def test_low_ratio_is_medium(self):
        results = {
            "vt": ThreatIntelResult(source="vt", malicious=2, total=50),
        }
        assert ThreatIntelAnalyzer._aggregate_file_severity(results) == Severity.MEDIUM

    def test_multi_source_boosts_severity(self):
        results = {
            "vt": ThreatIntelResult(source="vt", malicious=8, total=50),
            "tb": ThreatIntelResult(source="tb", malicious=5, total=30),
            "otx": ThreatIntelResult(source="otx", malicious=1, total=1),
        }
        # 3 sources with hits → CRITICAL
        assert ThreatIntelAnalyzer._aggregate_file_severity(results) == Severity.CRITICAL

    def test_ioc_high_high_is_critical(self):
        results = {
            "vt": IOCIntelResult(source="vt", ioc_type="domain", ioc_value="x", threat_level="high"),
            "tb": IOCIntelResult(source="tb", ioc_type="domain", ioc_value="x", threat_level="high"),
        }
        assert ThreatIntelAnalyzer._aggregate_ioc_severity(results) == Severity.CRITICAL

    def test_ioc_single_high_is_high(self):
        results = {
            "vt": IOCIntelResult(source="vt", ioc_type="ip", ioc_value="x", threat_level="high"),
        }
        assert ThreatIntelAnalyzer._aggregate_ioc_severity(results) == Severity.HIGH

    def test_ioc_medium_medium_is_high(self):
        results = {
            "vt": IOCIntelResult(source="vt", ioc_type="url", ioc_value="x", threat_level="medium"),
            "tb": IOCIntelResult(source="tb", ioc_type="url", ioc_value="x", threat_level="medium"),
        }
        assert ThreatIntelAnalyzer._aggregate_ioc_severity(results) == Severity.HIGH
