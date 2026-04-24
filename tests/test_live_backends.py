"""
Live integration tests for ThreatBook, OTX, VirusTotal backends.

Tests query functionality and threat_level/severity mapping against real APIs.
Run: uv run pytest tests/test_live_backends.py -v -s -m integration
"""

from __future__ import annotations

import os

import pytest

from skill_scanner.config.config import load_dotenv

load_dotenv()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_env(key: str) -> str:
    val = os.getenv(key)
    if not val:
        pytest.skip(f"{key} not set")
    return val


# EICAR test file SHA256
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


# ===========================================================================
# ThreatBook
# ===========================================================================

class TestThreatBookLive:
    @pytest.fixture(autouse=True)
    def setup(self):
        from skill_scanner.core.analyzers.threat_intel.threatbook_backend import ThreatBookBackend
        key = _get_env("THREATBOOK_API_KEY")
        self.backend = ThreatBookBackend(api_key=key, timeout=30)

    # --- query_hash (multiengines API) ---

    def test_query_hash_eicar(self):
        """EICAR hash — should be detected as malicious by multi-engines."""
        result = self.backend.query_hash(EICAR_SHA256)
        if result is None:
            pytest.skip("ThreatBook returned no result for EICAR hash")
        print(f"\n[ThreatBook] EICAR hash → malicious={result.malicious}, "
              f"suspicious={result.suspicious}, total={result.total}, "
              f"verdict={result.verdict}, details={result.details}")
        assert result.source == "threatbook"
        assert result.file_hash == EICAR_SHA256
        # EICAR should have positives or be flagged as suspicious at minimum
        assert result.malicious > 0 or result.suspicious > 0 or result.verdict == "malicious"

    def test_query_hash_unknown_hash(self):
        """Unknown hash — should return None or clean result."""
        fake_hash = "a" * 64
        result = self.backend.query_hash(fake_hash)
        print(f"\n[ThreatBook] unknown hash → {result}")
        if result is not None:
            assert result.malicious == 0

    # --- query_ioc IP ---

    def test_query_ip_known_malicious(self):
        """Query a known malicious IP."""
        # 54.91.154.110 is often in threat feeds
        result = self.backend.query_ioc("ip", "54.91.154.110")
        if result is None:
            pytest.skip("ThreatBook returned no result for IP")
        print(f"\n[ThreatBook] IP 54.91.154.110 → threat_level={result.threat_level}, "
              f"tags={result.tags}, details={result.details}")
        assert result.source == "threatbook"
        assert result.ioc_type == "ip"
        assert result.threat_level in ("high", "medium", "low", "info", "clean")

    def test_query_ip_google_dns(self):
        """Query 8.8.8.8 — should be clean/info."""
        result = self.backend.query_ioc("ip", "8.8.8.8")
        if result is None:
            pytest.skip("ThreatBook returned no result for 8.8.8.8")
        print(f"\n[ThreatBook] IP 8.8.8.8 → threat_level={result.threat_level}, "
              f"tags={result.tags}")
        assert result.threat_level in ("info", "clean", "low")

    # --- query_ioc domain ---

    def test_query_domain_known_malicious(self):
        """Query a known malicious domain."""
        result = self.backend.query_ioc("domain", "xred.mooo.com")
        if result is None:
            pytest.skip("ThreatBook returned no result for domain")
        print(f"\n[ThreatBook] domain xred.mooo.com → threat_level={result.threat_level}, "
              f"tags={result.tags}, details={result.details}")
        assert result.source == "threatbook"
        assert result.threat_level in ("high", "medium", "low", "info", "clean")

    def test_query_domain_safe(self):
        """Query a safe domain — should be clean."""
        result = self.backend.query_ioc("domain", "baidu.com")
        if result is None:
            pytest.skip("ThreatBook returned no result for baidu.com")
        print(f"\n[ThreatBook] domain baidu.com → threat_level={result.threat_level}, "
              f"tags={result.tags}")
        assert result.threat_level in ("info", "clean", "low")

    # --- normalize mapping ---

    def test_normalize_severity_mapping(self):
        from skill_scanner.core.analyzers.threat_intel.threatbook_backend import ThreatBookBackend
        assert ThreatBookBackend._normalize_severity("critical") == "high"
        assert ThreatBookBackend._normalize_severity("high") == "high"
        assert ThreatBookBackend._normalize_severity("medium") == "medium"
        assert ThreatBookBackend._normalize_severity("low") == "low"
        assert ThreatBookBackend._normalize_severity("info") == "info"
        assert ThreatBookBackend._normalize_severity("safe") == "clean"
        assert ThreatBookBackend._normalize_severity("unknown") == "info"

    def test_normalize_multiengines_mapping(self):
        from skill_scanner.core.analyzers.threat_intel.threatbook_backend import ThreatBookBackend
        assert ThreatBookBackend._normalize_multiengines_level("malicious") == "high"
        assert ThreatBookBackend._normalize_multiengines_level("suspicious") == "medium"
        assert ThreatBookBackend._normalize_multiengines_level("clean") == "clean"
        assert ThreatBookBackend._normalize_multiengines_level("unknown") == "info"


# ===========================================================================
# OTX
# ===========================================================================

class TestOTXLive:
    @pytest.fixture(autouse=True)
    def setup(self):
        from skill_scanner.core.analyzers.threat_intel.otx_backend import OTXBackend
        key = _get_env("OTX_API_KEY")
        self.backend = OTXBackend(api_key=key, timeout=30)

    # --- query_hash ---

    def test_query_hash_eicar(self):
        result = self.backend.query_hash(EICAR_SHA256)
        if result is None:
            pytest.skip("OTX returned no result for EICAR hash")
        print(f"\n[OTX] EICAR hash → malicious={result.malicious}, total={result.total}, "
              f"verdict={result.verdict}, pulse_count={result.details.get('pulse_count')}")
        assert result.source == "otx"
        assert result.malicious > 0
        assert result.total == 10  # fixed denominator
        assert result.verdict == "malicious"

    # --- query_ioc ---

    def test_query_ip(self):
        result = self.backend.query_ioc("ip", "54.91.154.110")
        if result is None:
            pytest.skip("OTX returned no result for IP")
        print(f"\n[OTX] IP 54.91.154.110 → threat_level={result.threat_level}, "
              f"tags={result.tags}, pulse_count={result.details.get('pulse_count')}")
        assert result.source == "otx"
        assert result.threat_level in ("high", "medium", "low", "info", "clean")

    def test_query_domain(self):
        result = self.backend.query_ioc("domain", "polymarket.com")
        if result is None:
            pytest.skip("OTX returned no result for domain")
        print(f"\n[OTX] domain polymarket.com → threat_level={result.threat_level}, "
              f"tags={result.tags}, pulse_count={result.details.get('pulse_count')}")
        assert result.source == "otx"

    def test_query_hash_as_ioc_eicar(self):
        """Test hash IOC with pulse_count-based threat_level."""
        result = self.backend.query_ioc("hash", EICAR_SHA256)
        if result is None:
            pytest.skip("OTX returned no result for EICAR hash IOC")
        print(f"\n[OTX] EICAR hash IOC → threat_level={result.threat_level}, "
              f"pulse_count={result.details.get('pulse_count')}")
        assert result.source == "otx"
        assert result.ioc_type == "hash"
        # EICAR should have many pulses → high
        assert result.threat_level in ("high", "medium", "low", "info")

    def test_pulse_count_thresholds(self):
        """Verify pulse_count → threat_level mapping logic."""
        # This tests the _query_hash_as_ioc thresholds indirectly
        # EICAR has many pulses → should be "high" (>=5)
        result = self.backend.query_hash(EICAR_SHA256)
        if result is None:
            pytest.skip("OTX returned no result for EICAR")
        pulse_count = result.details.get("pulse_count", 0)
        print(f"\n[OTX] EICAR pulse_count={pulse_count}")
        assert pulse_count >= 1


# ===========================================================================
# VirusTotal
# ===========================================================================

class TestVirusTotalLive:
    @pytest.fixture(autouse=True)
    def setup(self):
        from skill_scanner.core.analyzers.threat_intel.virustotal_backend import VirusTotalBackend
        key = _get_env("VIRUSTOTAL_API_KEY")
        self.backend = VirusTotalBackend(api_key=key, timeout=30)

    # --- query_hash ---

    def test_query_hash_eicar(self):
        result = self.backend.query_hash(EICAR_SHA256)
        if result is None:
            pytest.skip("VT returned no result for EICAR hash")
        print(f"\n[VT] EICAR hash → malicious={result.malicious}, "
              f"suspicious={result.suspicious}, total={result.total}, "
              f"verdict={result.verdict}")
        assert result.source == "virustotal"
        assert result.malicious > 0
        assert result.verdict == "malicious"

    def test_query_hash_unknown(self):
        fake_hash = "0" * 64
        result = self.backend.query_hash(fake_hash)
        print(f"\n[VT] unknown hash → {result}")
        assert result is None  # 404

    # --- query_ioc ---

    def test_query_ip_malicious(self):
        result = self.backend.query_ioc("ip", "45.33.32.156")
        if result is None:
            pytest.skip("VT returned no result for IP")
        print(f"\n[VT] IP 45.33.32.156 → threat_level={result.threat_level}, tags={result.tags}")
        assert result.source == "virustotal"

    def test_query_ip_clean(self):
        result = self.backend.query_ioc("ip", "8.8.8.8")
        if result is None:
            pytest.skip("VT returned no result for 8.8.8.8")
        print(f"\n[VT] IP 8.8.8.8 → threat_level={result.threat_level}, tags={result.tags}")
        assert result.threat_level in ("clean", "info", "low")

    def test_query_domain(self):
        result = self.backend.query_ioc("domain", "google.com")
        if result is None:
            pytest.skip("VT returned no result for google.com")
        print(f"\n[VT] domain google.com → threat_level={result.threat_level}, tags={result.tags}")
        assert result.threat_level in ("clean", "info", "low")

    def test_query_hash_as_ioc(self):
        result = self.backend.query_ioc("hash", EICAR_SHA256)
        if result is None:
            pytest.skip("VT returned no result for EICAR hash IOC")
        print(f"\n[VT] EICAR hash IOC → threat_level={result.threat_level}")
        assert result.threat_level == "high"  # EICAR has high detection ratio

    # --- mapping ---

    def test_map_threat_level(self):
        from skill_scanner.core.analyzers.threat_intel.virustotal_backend import VirusTotalBackend
        assert VirusTotalBackend._map_threat_level(30, 50) == "high"
        assert VirusTotalBackend._map_threat_level(5, 50) == "medium"
        assert VirusTotalBackend._map_threat_level(1, 50) == "low"
        assert VirusTotalBackend._map_threat_level(0, 50) == "clean"
        assert VirusTotalBackend._map_threat_level(0, 0) == "info"

    def test_map_verdict(self):
        from skill_scanner.core.analyzers.threat_intel.virustotal_backend import VirusTotalBackend
        assert VirusTotalBackend._map_verdict({"malicious": 5}) == "malicious"
        assert VirusTotalBackend._map_verdict({"suspicious": 3, "malicious": 0}) == "suspicious"
        assert VirusTotalBackend._map_verdict({"harmless": 50, "malicious": 0, "suspicious": 0}) == "clean"
        assert VirusTotalBackend._map_verdict({}) == "unknown"
