"""
ThreatBook (微步在线) threat intelligence backend.

Supports file hash, IP, and domain reputation queries via ThreatBook v5 API.
File submission is not supported.
"""

from __future__ import annotations

import logging
from typing import ClassVar

import httpx

from .base import IOCIntelResult, ThreatIntelBackend, ThreatIntelResult

logger = logging.getLogger(__name__)

_TB_BASE_URL = "https://api.threatbook.cn/v5"


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
        """Query ThreatBook for a file hash."""
        try:
            resp = self._session.get(
                f"{self.base_url}/file/reputation",
                params={"apikey": self.api_key, "sha256": file_hash},
            )
            if resp.status_code != 200:
                logger.warning("ThreatBook API returned status %d", resp.status_code)
                return None

            data = resp.json()
            response_code = data.get("response_code", -1)
            if response_code != 0:
                return None

            verbose_msg = data.get("verbose_msg", "")
            threat_level = data.get("threat_level", "info")
            # ThreatBook may return multi-engine results
            positives = data.get("positives", 0)
            total = data.get("total", 0)

            # If no multi-engine data, derive from threat_level
            if total == 0:
                total = 1
                if threat_level in ("high", "critical"):
                    positives = 1

            return ThreatIntelResult(
                source="threatbook",
                malicious=positives,
                total=total,
                verdict=self._map_verdict(threat_level),
                permalink=data.get("permalink"),
                scan_date=data.get("scan_date"),
                details={"verbose_msg": verbose_msg, "threat_level": threat_level},
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
        """Query ThreatBook for an IP address."""
        resp = self._session.get(
            f"{self.base_url}/ip/reputation",
            params={"apikey": self.api_key, "resource": ip},
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
        if data.get("response_code", -1) != 0:
            return None

        threat_level = data.get("threat_level", "info")
        tags = data.get("tags", [])
        summary = data.get("summary", {})

        return IOCIntelResult(
            source="threatbook",
            ioc_type="ip",
            ioc_value=ip,
            threat_level=threat_level,
            tags=tuple(tags),
            permalink=data.get("permalink"),
            details={"summary": summary, "severity": data.get("severity")},
        )

    def _query_domain(self, domain: str) -> IOCIntelResult | None:
        """Query ThreatBook for a domain."""
        if not domain:
            return None
        resp = self._session.get(
            f"{self.base_url}/domain/reputation",
            params={"apikey": self.api_key, "resource": domain},
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
        if data.get("response_code", -1) != 0:
            return None

        threat_level = data.get("threat_level", "info")
        tags = data.get("tags", [])
        summary = data.get("summary", {})

        return IOCIntelResult(
            source="threatbook",
            ioc_type="domain",
            ioc_value=domain,
            threat_level=threat_level,
            tags=tuple(tags),
            permalink=data.get("permalink"),
            details={"summary": summary},
        )

    def _query_hash_as_ioc(self, file_hash: str) -> IOCIntelResult | None:
        """Query ThreatBook for a file hash, returning IOC-style result."""
        result = self.query_hash(file_hash)
        if result is None:
            return None
        return IOCIntelResult(
            source="threatbook",
            ioc_type="hash",
            ioc_value=file_hash,
            threat_level=result.details.get("threat_level", "info"),
            tags=(),
            permalink=result.permalink,
        )

    @staticmethod
    def _extract_domain_from_url(url: str) -> str:
        """Extract domain from a URL for ThreatBook domain lookup."""
        try:
            # Simple extraction: strip protocol and path
            stripped = url.split("://", 1)[-1]
            domain = stripped.split("/", 1)[0]
            # Remove port
            domain = domain.split(":", 1)[0]
            return domain
        except (IndexError, ValueError):
            return ""

    @staticmethod
    def _map_verdict(threat_level: str) -> str:
        """Map ThreatBook threat_level to verdict."""
        mapping = {
            "critical": "malicious",
            "high": "malicious",
            "medium": "suspicious",
            "low": "suspicious",
            "info": "clean",
            "safe": "clean",
        }
        return mapping.get(threat_level, "unknown")
