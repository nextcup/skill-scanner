"""
Zhongfu Threat Intelligence Platform (中孚威胁情报) backend.

Provides batch IOC query via /batch/ioc/query endpoint.
Supports IP, domain, and URL lookups. Does not support hash or file submission.
"""

from __future__ import annotations

import logging
from pathlib import Path

import httpx

from .base import IOCIntelResult, ThreatIntelBackend, ThreatIntelResult

logger = logging.getLogger(__name__)


class ZftipBackend:
    """Zhongfu Threat Intelligence Platform backend.

    API: POST {api_url}/batch/ioc/query
    Body: {"api_key": "...", "param": "ioc1,ioc2,..."}
    Response: {"code": 200, "data": [{"ioc_value": [...]}, ...]}
    """

    name: str = "zftip"
    supports_hash_lookup: bool = False
    supports_file_submission: bool = False
    supported_ioc_types: list[str] = ["ip", "domain", "url"]

    def __init__(
        self,
        api_url: str,
        api_key: str,
        timeout: int = 10,
    ):
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self._session = httpx.Client(
            timeout=timeout,
            headers={"Content-Type": "application/json"},
        )

    def query_hash(self, file_hash: str) -> ThreatIntelResult | None:
        """Zftip does not support hash lookup."""
        return None

    def submit_file(self, file_path: Path, file_hash: str) -> ThreatIntelResult | None:
        """Zftip does not support file submission."""
        return None

    def query_ioc(self, ioc_type: str, ioc_value: str) -> IOCIntelResult | None:
        """Query zftip for an IOC via the batch endpoint."""
        if ioc_type not in self.supported_ioc_types:
            return None

        try:
            resp = self._session.post(
                f"{self.api_url}/batch/ioc/query",
                json={"api_key": self.api_key, "param": ioc_value},
            )
            if resp.status_code != 200:
                logger.warning(
                    "Zftip API returned status %d for %s",
                    resp.status_code,
                    ioc_value,
                )
                return None

            body = resp.json()
            if body.get("code") != 200:
                logger.warning(
                    "Zftip API returned code %s for %s",
                    body.get("code"),
                    ioc_value,
                )
                return None

            data = body.get("data", [])
            return self._parse_response(data, ioc_type, ioc_value)
        except httpx.RequestError as e:
            logger.warning("Zftip IOC query failed for %s %s: %s", ioc_type, ioc_value, e)
            return None

    def _parse_response(
        self,
        data: list[dict],
        ioc_type: str,
        ioc_value: str,
    ) -> IOCIntelResult | None:
        """Parse zftip batch response and extract result for the target IOC."""
        for item in data:
            if ioc_value not in item:
                continue

            results = item[ioc_value]
            if not results:
                # Empty array = no threat intelligence
                return None

            info = results[0]

            # Extract labels (threat tags)
            labels = info.get("label") or info.get("open_label") or []

            # Determine threat level from category field
            # category: 3=恶意, 2=可疑, 1=未知, 0=白名单
            category = info.get("category")
            if category == 3:
                threat_level = "high"
            elif category == 2:
                threat_level = "medium"
            elif category == 0:
                threat_level = "clean"
            else:
                # category==1 or missing → info
                threat_level = "info"

            # Extract details
            details: dict = {}
            for key in (
                "credit_score",
                "category",
                "org",
                "registrar",
                "registered_date",
                "expired_date",
                "email",
                "country",
            ):
                if key in info:
                    details[key] = info[key]

            if "dns_parsing_records" in info:
                details["dns_records"] = info["dns_parsing_records"]
            if "source_mapping" in info:
                details["source_mapping"] = info["source_mapping"]
            if "open_source_mapping" in info:
                details["open_source_mapping"] = info["open_source_mapping"]

            return IOCIntelResult(
                source="zftip",
                ioc_type=ioc_type,
                ioc_value=ioc_value,
                threat_level=threat_level,
                tags=tuple(labels) if labels else (),
                permalink=None,
                details=details,
            )

        # IOC not found in response
        return None