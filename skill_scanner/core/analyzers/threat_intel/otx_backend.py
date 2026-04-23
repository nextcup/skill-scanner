"""
AlienVault OTX (Open Threat Exchange) threat intelligence backend.

Free threat intelligence platform supporting hash, IP, domain, and URL lookups.
File submission is not supported.
"""

from __future__ import annotations

import logging
from pathlib import Path

import httpx

from .base import IOCIntelResult, ThreatIntelBackend, ThreatIntelResult

logger = logging.getLogger(__name__)

_OTX_BASE_URL = "https://otx.alienvault.com"


class OTXBackend:
    """AlienVault OTX threat intelligence backend."""

    name: str = "otx"
    supports_hash_lookup: bool = True
    supports_file_submission: bool = False
    supported_ioc_types: list[str] = ["url", "domain", "ip", "hash"]

    def __init__(
        self,
        api_key: str,
        base_url: str = _OTX_BASE_URL,
        timeout: int = 10,
    ):
        self.api_key = api_key
        self.base_url = base_url
        self.timeout = timeout
        self._session = httpx.Client(
            timeout=timeout,
            headers={"X-OTX-API-KEY": api_key, "Accept": "application/json"},
        )

    def query_hash(self, file_hash: str) -> ThreatIntelResult | None:
        """Query OTX for a file hash."""
        try:
            resp = self._session.get(
                f"{self.base_url}/api/v1/indicators/file/{file_hash}/general",
            )
            if resp.status_code == 404:
                return None
            if resp.status_code != 200:
                logger.warning("OTX API returned status %d", resp.status_code)
                return None

            data = resp.json()
            pulse_info = data.get("pulse_info", {})
            pulse_count = pulse_info.get("count", 0)
            pulses = pulse_info.get("pulses", [])

            # OTX doesn't have AV engines; use pulse count as indicator
            # More pulses = more threat intelligence consensus
            malicious = 1 if pulse_count > 0 else 0
            verdict = "malicious" if pulse_count > 0 else "clean"

            # Extract AV classification if available
            av_classification = {}
            general = data.get("general", {})
            if general.get("av_classification"):
                av_classification = general["av_classification"]

            # Extract tags from pulses
            all_tags: list[str] = []
            for pulse in pulses[:3]:
                all_tags.extend(pulse.get("tags", []))

            return ThreatIntelResult(
                source="otx",
                malicious=malicious,
                total=max(pulse_count, 1),
                verdict=verdict,
                permalink=f"https://otx.alienvault.com/indicator/file/{file_hash}",
                details={
                    "pulse_count": pulse_count,
                    "pulse_names": [p.get("name", "") for p in pulses[:5]],
                    "tags": list(set(all_tags))[:10],
                    "av_classification": av_classification,
                },
                file_hash=file_hash,
            )
        except httpx.RequestError as e:
            logger.warning("OTX hash query failed: %s", e)
            return None

    def submit_file(self, file_path: Path, file_hash: str) -> ThreatIntelResult | None:
        """OTX does not support file submission."""
        return None

    def query_ioc(self, ioc_type: str, ioc_value: str) -> IOCIntelResult | None:
        """Query OTX for an IOC (IP, domain, URL, or hash)."""
        try:
            if ioc_type == "ip":
                return self._query_ip(ioc_value)
            elif ioc_type == "domain":
                return self._query_domain(ioc_value)
            elif ioc_type == "url":
                return self._query_url(ioc_value)
            elif ioc_type == "hash":
                return self._query_hash_as_ioc(ioc_value)
            return None
        except httpx.RequestError as e:
            logger.warning("OTX IOC query failed for %s %s: %s", ioc_type, ioc_value, e)
            return None

    def _query_ip(self, ip: str) -> IOCIntelResult | None:
        """Query OTX for an IP address."""
        resp = self._session.get(
            f"{self.base_url}/api/v1/indicators/IPv4/{ip}/general",
        )
        if resp.status_code == 404:
            return None
        if resp.status_code != 200:
            return None
        return self._parse_indicator_response(resp.json(), "ip", ip)

    def _query_domain(self, domain: str) -> IOCIntelResult | None:
        """Query OTX for a domain."""
        resp = self._session.get(
            f"{self.base_url}/api/v1/indicators/domain/{domain}/general",
        )
        if resp.status_code == 404:
            return None
        if resp.status_code != 200:
            return None
        return self._parse_indicator_response(resp.json(), "domain", domain)

    def _query_url(self, url: str) -> IOCIntelResult | None:
        """Query OTX for a URL."""
        resp = self._session.get(
            f"{self.base_url}/api/v1/indicators/url/{url}/general",
        )
        if resp.status_code == 404:
            return None
        if resp.status_code != 200:
            return None
        return self._parse_indicator_response(resp.json(), "url", url)

    def _query_hash_as_ioc(self, file_hash: str) -> IOCIntelResult | None:
        """Query OTX for a file hash, returning IOC-style result."""
        result = self.query_hash(file_hash)
        if result is None:
            return None
        return IOCIntelResult(
            source="otx",
            ioc_type="hash",
            ioc_value=file_hash,
            threat_level="high" if result.malicious > 0 else "clean",
            tags=tuple(result.details.get("tags", [])),
            permalink=result.permalink,
        )

    def _parse_indicator_response(
        self, data: dict, ioc_type: str, ioc_value: str,
    ) -> IOCIntelResult:
        """Parse OTX indicator response into IOCIntelResult."""
        pulse_info = data.get("pulse_info", {})
        pulse_count = pulse_info.get("count", 0)
        pulses = pulse_info.get("pulses", [])

        # Determine threat level from pulse count and pulse adversary info
        threat_level = "info"
        if pulse_count >= 5:
            threat_level = "high"
        elif pulse_count >= 2:
            threat_level = "medium"
        elif pulse_count >= 1:
            threat_level = "low"

        # Check if any pulse indicates targeted/adversary activity
        tags: list[str] = []
        for pulse in pulses[:5]:
            tags.extend(pulse.get("tags", []))
            adversary = pulse.get("adversary", "")
            if adversary:
                tags.append(f"adversary:{adversary}")

        indicator_path = f"{ioc_type}/{ioc_value}" if ioc_type != "url" else f"url"
        return IOCIntelResult(
            source="otx",
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            threat_level=threat_level,
            tags=tuple(list(set(tags))[:10]),
            permalink=f"https://otx.alienvault.com/indicator/{indicator_path}",
            details={
                "pulse_count": pulse_count,
                "pulse_names": [p.get("name", "") for p in pulses[:5]],
            },
        )
