"""
ThreatBook (微步在线) threat intelligence backend.

Supports file hash, IP, and domain reputation queries via ThreatBook v3 API.
File submission is not supported.
"""

from __future__ import annotations

import logging
from typing import ClassVar

import httpx

from .base import IOCIntelResult, ThreatIntelBackend, ThreatIntelResult

logger = logging.getLogger(__name__)

_TB_BASE_URL = "https://api.threatbook.cn/v3"


class ThreatBookBackend:
    """ThreatBook (微步在线) threat intelligence backend."""

    name: str = "threatbook"
    supports_hash_lookup: bool = True
    supports_file_submission: bool = False
    supported_ioc_types: list[str] = ["url", "domain", "ip", "hash"]

    def __init__(
        self,
        api_key: str,
        base_url: str = _TB_BASE_URL,
        timeout: int = 10,
    ):
        self.api_key = api_key
        self.base_url = base_url
        self.timeout = timeout
        self._session = httpx.Client(
            timeout=timeout,
            headers={"Accept": "application/json"},
        )

    def query_hash(self, file_hash: str) -> ThreatIntelResult | None:
        """Query ThreatBook for a file hash via multi-engines API."""
        try:
            resp = self._session.get(
                f"{self.base_url}/file/report/multiengines",
                params={"apikey": self.api_key, "sha256": file_hash},
            )
            if resp.status_code != 200:
                logger.warning("ThreatBook API returned status %d", resp.status_code)
                return None

            data = resp.json()
            response_code = data.get("response_code", -1)
            if response_code != 0:
                return None

            me = data.get("data", {}).get("multiengines", {})
            threat_level_raw = me.get("threat_level", "unknown")
            positives = me.get("positives", 0)
            total = me.get("total", 0)

            # When no multi-engine data, use suspicious to express uncertainty
            # (Fix #8: avoid inflating malicious ratio)
            suspicious = 0
            if total == 0:
                total = 10  # baseline denominator
                if threat_level_raw == "malicious":
                    suspicious = 5  # 50% suspicious
                elif threat_level_raw == "suspicious":
                    suspicious = 3  # 30% suspicious
                # malicious stays 0 — don't fabricate detection ratio

            return ThreatIntelResult(
                source="threatbook",
                malicious=positives,
                suspicious=suspicious,
                total=total,
                verdict=self._map_verdict(threat_level_raw),
                permalink=data.get("permalink"),
                scan_date=data.get("scan_date"),
                details={"multiengines_threat_level": threat_level_raw},
                file_hash=file_hash,
            )
        except httpx.RequestError as e:
            logger.warning("ThreatBook hash query failed: %s", e)
            return None

    def submit_file(self, file_path, file_hash: str) -> ThreatIntelResult | None:
        """ThreatBook does not support file submission."""
        return None

    def query_ioc(self, ioc_type: str, ioc_value: str) -> IOCIntelResult | None:
        """Query ThreatBook for an IOC (IP, domain, or URL)."""
        try:
            if ioc_type == "ip":
                return self._query_ip(ioc_value)
            elif ioc_type == "domain":
                return self._query_domain(ioc_value)
            elif ioc_type == "url":
                # ThreatBook URL query uses domain extraction as fallback
                return self._query_domain(self._extract_domain_from_url(ioc_value))
            elif ioc_type == "hash":
                return self._query_hash_as_ioc(ioc_value)
            return None
        except httpx.RequestError as e:
            logger.warning("ThreatBook IOC query failed for %s %s: %s", ioc_type, ioc_value, e)
            return None

    def _query_ip(self, ip: str) -> IOCIntelResult | None:
        """Query ThreatBook for an IP address via IP Reputation API."""
        resp = self._session.get(
            f"{self.base_url}/scene/ip_reputation",
            params={"apikey": self.api_key, "resource": ip},
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
        if data.get("response_code", -1) != 0:
            return None

        # Response: {"data": {"<ip>": {"severity": "...", "is_malicious": bool, "tags_classes": [...]}}}
        inner_data = data.get("data", {})
        ip_info = inner_data.get(ip, {})
        if not ip_info:
            return None

        severity = ip_info.get("severity", "info")
        threat_level = self._normalize_severity(severity)
        tags = self._extract_tags(ip_info.get("tags_classes", []))

        return IOCIntelResult(
            source="threatbook",
            ioc_type="ip",
            ioc_value=ip,
            threat_level=threat_level,
            tags=tuple(tags),
            permalink=ip_info.get("permalink"),
            details={
                "is_malicious": ip_info.get("is_malicious", False),
                "severity": severity,
            },
        )

    def _query_domain(self, domain: str) -> IOCIntelResult | None:
        """Query ThreatBook for a domain via DNS Scene API."""
        if not domain:
            return None
        resp = self._session.get(
            f"{self.base_url}/scene/dns",
            params={"apikey": self.api_key, "resource": domain},
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
        if data.get("response_code", -1) != 0:
            return None

        # Response: {"data": {"domains": {"<domain>": {"severity": "...", "is_malicious": bool, ...}}}}
        inner = data.get("data", {})
        domains_data = inner.get("domains", {})
        domain_info = domains_data.get(domain, {})
        if not domain_info:
            return None

        severity = domain_info.get("severity", "info")
        threat_level = self._normalize_severity(severity)
        tags = self._extract_tags(domain_info.get("tags_classes", []))

        return IOCIntelResult(
            source="threatbook",
            ioc_type="domain",
            ioc_value=domain,
            threat_level=threat_level,
            tags=tuple(tags),
            permalink=domain_info.get("permalink"),
            details={
                "is_malicious": domain_info.get("is_malicious", False),
                "severity": severity,
            },
        )

    def _query_hash_as_ioc(self, file_hash: str) -> IOCIntelResult | None:
        """Query ThreatBook for a file hash, returning IOC-style result."""
        result = self.query_hash(file_hash)
        if result is None:
            return None
        # Derive threat_level from multiengines verdict
        me_level = result.details.get("multiengines_threat_level", "unknown")
        threat_level = self._normalize_multiengines_level(me_level)
        return IOCIntelResult(
            source="threatbook",
            ioc_type="hash",
            ioc_value=file_hash,
            threat_level=threat_level,
            tags=(),
            permalink=result.permalink,
        )

    @staticmethod
    def _extract_tags(tags_classes: list[dict]) -> list[str]:
        """Extract tag values from tags_classes.

        ThreatBook tags may be plain strings or dicts with 'value' key.
        """
        result: list[str] = []
        for tc in tags_classes:
            for tag in tc.get("tags", []):
                if isinstance(tag, str):
                    result.append(tag)
                elif isinstance(tag, dict) and tag.get("value"):
                    result.append(tag["value"])
        return result

    @staticmethod
    def _extract_domain_from_url(url: str) -> str:
        """Extract domain from a URL for ThreatBook domain lookup."""
        try:
            stripped = url.split("://", 1)[-1]
            domain = stripped.split("/", 1)[0]
            # Remove port
            domain = domain.split(":", 1)[0]
            return domain
        except (IndexError, ValueError):
            return ""

    @staticmethod
    def _normalize_severity(severity: str) -> str:
        """Map ThreatBook API severity to standard threat_level.

        Used for IP and domain queries where ThreatBook returns severity field.
        """
        mapping = {
            "critical": "high",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "info": "info",
            "safe": "clean",
        }
        return mapping.get(severity, "info")

    @staticmethod
    def _normalize_multiengines_level(threat_level: str) -> str:
        """Map ThreatBook multiengines threat_level to standard threat_level."""
        mapping = {
            "malicious": "high",
            "suspicious": "medium",
            "clean": "clean",
            "unknown": "info",
        }
        return mapping.get(threat_level, "info")

    @staticmethod
    def _map_verdict(threat_level: str) -> str:
        """Map multiengines threat_level to verdict."""
        mapping = {
            "malicious": "malicious",
            "suspicious": "suspicious",
            "clean": "clean",
            "unknown": "unknown",
        }
        return mapping.get(threat_level, "unknown")
