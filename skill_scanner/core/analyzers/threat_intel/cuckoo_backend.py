"""
Cuckoo Sandbox threat intelligence backend.

Supports file hash lookups and file submission for dynamic analysis
via Cuckoo's REST API (self-hosted).
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

import httpx

from .base import IOCIntelResult, ThreatIntelBackend, ThreatIntelResult

logger = logging.getLogger(__name__)


class CuckooBackend:
    """Cuckoo Sandbox REST API backend (self-hosted)."""

    name: str = "cuckoo"
    supports_hash_lookup: bool = True
    supports_file_submission: bool = True
    supported_ioc_types: list[str] = ["hash"]  # Cuckoo only supports file-based analysis

    def __init__(
        self,
        api_url: str,
        api_key: str | None = None,
        timeout: int = 10,
        poll_interval: int = 10,
        max_poll_attempts: int = 12,
    ):
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.poll_interval = poll_interval
        self.max_poll_attempts = max_poll_attempts

        headers = {"Accept": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        self._session = httpx.Client(timeout=timeout, headers=headers)

    def query_hash(self, file_hash: str) -> ThreatIntelResult | None:
        """Query Cuckoo for a file hash (checks if analyzed before)."""
        try:
            resp = self._session.get(f"{self.api_url}/files/view/sha256/{file_hash}")
            if resp.status_code == 404:
                return None
            if resp.status_code != 200:
                logger.warning("Cuckoo API returned status %d", resp.status_code)
                return None

            data = resp.json()
            # Cuckoo file view doesn't include analysis results directly,
            # need to find a task for this file
            task_id = data.get("task_ids", [])
            if not task_id:
                return None

            # Get the most recent task report
            latest_task_id = task_id[-1]
            return self._get_task_result(latest_task_id, file_hash)

        except httpx.RequestError as e:
            logger.warning("Cuckoo hash query failed: %s", e)
            return None

    def submit_file(self, file_path: Path, file_hash: str) -> ThreatIntelResult | None:
        """Submit a file to Cuckoo for dynamic analysis."""
        try:
            with open(file_path, "rb") as f:
                files = {"file": (file_path.name, f)}
                resp = self._session.post(
                    f"{self.api_url}/tasks/create/file",
                    files=files,
                    timeout=60,
                )

            if resp.status_code != 200:
                logger.warning("Cuckoo file submission failed with status %d", resp.status_code)
                return None

            task_id = resp.json().get("task_id")
            if not task_id:
                logger.warning("Cuckoo did not return task_id")
                return None

            logger.info("Submitted to Cuckoo, task_id: %s", task_id)

            # Poll for analysis completion
            for attempt in range(self.max_poll_attempts):
                time.sleep(self.poll_interval)
                report = self._get_task_result(task_id, file_hash)
                if report is not None:
                    return report
                # Check if task is still running
                status_resp = self._session.get(f"{self.api_url}/tasks/view/{task_id}")
                if status_resp.status_code == 200:
                    status = status_resp.json().get("task", {}).get("status", "")
                    if status in ("reported", "failed"):
                        if status == "failed":
                            logger.warning("Cuckoo task %s failed", task_id)
                            return None
                        return self._get_task_result(task_id, file_hash)

            logger.warning("Cuckoo analysis timed out after %ds", self.max_poll_attempts * self.poll_interval)
            return None

        except (httpx.RequestError, OSError) as e:
            logger.warning("Cuckoo file submission failed: %s", e)
            return None

    def query_ioc(self, ioc_type: str, ioc_value: str) -> IOCIntelResult | None:
        """Cuckoo does not support non-hash IOC queries."""
        return None

    def _get_task_result(self, task_id: int, file_hash: str) -> ThreatIntelResult | None:
        """Get analysis result from a Cuckoo task report."""
        try:
            resp = self._session.get(f"{self.api_url}/tasks/report/{task_id}")
            if resp.status_code != 200:
                return None

            data = resp.json()
            info = data.get("info", {})
            signatures = data.get("signatures", [])
            score = info.get("score", 0)

            # Map Cuckoo score to malicious indicators
            # Cuckoo score: 0 (clean) to 10 (very malicious)
            malicious = 1 if score >= 4 else 0
            suspicious = 1 if 2 <= score < 4 else 0

            # Extract signature descriptions as tags
            sig_tags = tuple(
                sig.get("name", "") for sig in signatures[:10] if sig.get("name")
            )

            return ThreatIntelResult(
                source="cuckoo",
                malicious=malicious,
                suspicious=suspicious,
                total=1,
                verdict=self._map_score(score),
                permalink=f"{self.api_url}/analysis/{task_id}/summary",
                scan_date=info.get("started_on"),
                details={
                    "cuckoo_score": score,
                    "signatures": [s.get("description", s.get("name", "")) for s in signatures[:5]],
                },
                file_hash=file_hash,
            )
        except (httpx.RequestError, ValueError) as e:
            logger.warning("Cuckoo report retrieval failed: %s", e)
            return None

    @staticmethod
    def _map_score(score: int) -> str:
        """Map Cuckoo score to verdict."""
        if score >= 6:
            return "malicious"
        if score >= 4:
            return "suspicious"
        if score > 0:
            return "low"
        return "clean"
