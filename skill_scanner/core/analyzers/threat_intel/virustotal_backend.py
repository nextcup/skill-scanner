"""
VirusTotal threat intelligence backend.

Wraps VirusTotal v3 API for file hash lookups, IOC queries (URL, domain, IP),
and optional file submission.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import time
from pathlib import Path
from typing import ClassVar
from urllib.parse import quote

import httpx

from .base import IOCIntelResult, ThreatIntelBackend, ThreatIntelResult

logger = logging.getLogger(__name__)

_VT_BASE_URL = "https://www.virustotal.com/api/v3"


class VirusTotalBackend:
    """VirusTotal v3 API backend."""

    name: str = "virustotal"
    supports_hash_lookup: bool = True
    supports_file_submission: bool = True
    supported_ioc_types: list[str] = ["url", "domain", "ip", "hash"]

    def __init__(
        self,
        api_key: str,
        base_url: str = _VT_BASE_URL,
        timeout: int = 10,
    ):
        self.api_key = api_key
        self.base_url = base_url
        self.timeout = timeout
        self._session = httpx.Client(
            timeout=timeout,
            headers={"x-apikey": api_key, "Accept": "application/json"},
        )

    def query_hash(self, file_hash: str) -> ThreatIntelResult | None:
        """Query VirusTotal for a file hash."""
        try:
            resp = self._session.get(f"{self.base_url}/files/{file_hash}")
            if resp.status_code == 404:
                return None
            if resp.status_code == 429:
                logger.warning("VirusTotal rate limit exceeded")
                return None
            if resp.status_code != 200:
                logger.warning("VirusTotal API returned status %d", resp.status_code)
                return None

            data = resp.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return ThreatIntelResult(
                source="virustotal",
                malicious=stats.get("malicious", 0),
                suspicious=stats.get("suspicious", 0),
                total=sum(stats.values()),
                verdict=self._map_verdict(stats),
                permalink=f"https://www.virustotal.com/gui/file/{file_hash}",
                scan_date=data.get("data", {}).get("attributes", {}).get("last_analysis_date"),
                file_hash=file_hash,
            )
        except httpx.RequestError as e:
            logger.warning("VirusTotal hash query failed: %s", e)
            return None

    def submit_file(self, file_path: Path, file_hash: str) -> ThreatIntelResult | None:
        """Upload a file to VirusTotal for scanning."""
        try:
            file_size = file_path.stat().st_size
            if file_size > 32 * 1024 * 1024:
                logger.warning("File too large for VT upload: %s (%d bytes)", file_path.name, file_size)
                return None

            with open(file_path, "rb") as f:
                files = {"file": (file_path.name, f)}
                resp = self._session.post(f"{self.base_url}/files", files=files, timeout=60)

            if resp.status_code != 200:
                logger.warning("VT upload failed with status %d", resp.status_code)
                return None

            analysis_id = resp.json().get("data", {}).get("id")
            if not analysis_id:
                return None

            # Poll for analysis completion
            for attempt in range(6):
                time.sleep(10)
                poll_resp = self._session.get(f"{self.base_url}/analyses/{analysis_id}")
                if poll_resp.status_code == 200:
                    poll_data = poll_resp.json()
                    status = poll_data.get("data", {}).get("attributes", {}).get("status")
                    if status == "completed":
                        return self.query_hash(file_hash)

            logger.warning("VT analysis still pending after 60s")
            return self.query_hash(file_hash)

        except (httpx.RequestError, OSError) as e:
            logger.warning("VT file upload failed: %s", e)
            return None

    def query_ioc(self, ioc_type: str, ioc_value: str) -> IOCIntelResult | None:
        """Query VirusTotal for an IOC (URL, domain, or IP)."""
        try:
            if ioc_type == "url":
                return self._query_url(ioc_value)
            elif ioc_type == "domain":
                return self._query_domain(ioc_value)
            elif ioc_type == "ip":
                return self._query_ip(ioc_value)
            elif ioc_type == "hash":
                return self._query_hash_as_ioc(ioc_value)
            return None
        except httpx.RequestError as e:
            logger.warning("VT IOC query failed for %s %s: %s", ioc_type, ioc_value, e)
            return None

    def _query_url(self, url: str) -> IOCIntelResult | None:
        """Query VT for a URL."""
        url_id = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()
        resp = self._session.get(f"{self.base_url}/urls/{url_id}")
        if resp.status_code == 404:
            return None
        if resp.status_code != 200:
            return None
        return self._parse_ioc_response(resp.json(), "url", url, f"https://www.virustotal.com/gui/url/{url_id}")

    def _query_domain(self, domain: str) -> IOCIntelResult | None:
        """Query VT for a domain."""
        resp = self._session.get(f"{self.base_url}/domains/{domain}")
        if resp.status_code == 404:
            return None
        if resp.status_code != 200:
            return None
        return self._parse_ioc_response(resp.json(), "domain", domain, f"https://www.virustotal.com/gui/domain/{domain}")

    def _query_ip(self, ip: str) -> IOCIntelResult | None:
        """Query VT for an IP address."""
        resp = self._session.get(f"{self.base_url}/ip_addresses/{ip}")
        if resp.status_code == 404:
            return None
        if resp.status_code != 200:
            return None
        return self._parse_ioc_response(resp.json(), "ip", ip, f"https://www.virustotal.com/gui/ip-address/{ip}")

    def _query_hash_as_ioc(self, file_hash: str) -> IOCIntelResult | None:
        """Query VT for a file hash, returning IOC-style result."""
        result = self.query_hash(file_hash)
        if result is None:
            return None
        return IOCIntelResult(
            source="virustotal",
            ioc_type="hash",
            ioc_value=file_hash,
            threat_level=self._map_threat_level(result.malicious, result.total),
            tags=(),
            permalink=result.permalink,
        )

    def _parse_ioc_response(
        self, data: dict, ioc_type: str, ioc_value: str, permalink: str,
    ) -> IOCIntelResult:
        """Parse a VT IOC response into IOCIntelResult."""
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values())
        tags_list = attrs.get("tags", [])

        return IOCIntelResult(
            source="virustotal",
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            threat_level=self._map_threat_level(malicious, total),
            tags=tuple(tags_list[:10]),
            permalink=permalink,
        )

    @staticmethod
    def _map_verdict(stats: dict) -> str:
        """Map VT stats to verdict string."""
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        if malicious > 0:
            return "malicious"
        if suspicious > 0:
            return "suspicious"
        total = sum(stats.values())
        if total > 0:
            return "clean"
        return "unknown"

    @staticmethod
    def _map_threat_level(malicious: int, total: int) -> str:
        """Map VT detection ratio to threat level."""
        if total == 0:
            return "info"
        ratio = malicious / total
        if ratio >= 0.3:
            return "high"
        if ratio >= 0.1:
            return "medium"
        if malicious > 0:
            return "low"
        return "clean"
