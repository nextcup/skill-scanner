"""
Base types and protocol for threat intelligence backends.

Defines the data models (ThreatIntelResult, IOCItem, IOCIntelResult) and
the ThreatIntelBackend protocol that each backend must implement.
"""

from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, runtime_checkable


# ---------------------------------------------------------------------------
# Binary file classification (extracted from VirusTotalAnalyzer)
# ---------------------------------------------------------------------------

BINARY_EXTENSIONS: frozenset[str] = frozenset({
    # Images
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp", ".tiff",
    # Documents
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    # Archives
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar", ".tgz",
    # Executables
    ".exe", ".dll", ".so", ".dylib", ".bin", ".com",
    # Other binaries
    ".wasm", ".class", ".jar", ".war",
})

EXCLUDED_EXTENSIONS: frozenset[str] = frozenset({
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".c", ".cpp", ".h", ".hpp",
    ".go", ".rs", ".rb", ".php", ".swift", ".kt", ".cs", ".vb",
    ".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".ini", ".conf", ".cfg",
    ".xml", ".html", ".css", ".scss", ".sass", ".less",
    ".sh", ".bash", ".zsh", ".fish", ".ps1", ".bat", ".cmd",
    ".sql", ".graphql", ".proto", ".thrift",
    ".rst", ".org", ".adoc", ".tex",
})


def is_binary_file(file_path: str) -> bool:
    """Check if a file should be scanned as a binary (not code/text)."""
    ext = Path(file_path).suffix.lower()
    if ext in EXCLUDED_EXTENSIONS:
        return False
    return ext in BINARY_EXTENSIONS


def calculate_sha256(file_path: Path) -> str:
    """Calculate SHA256 hash of a file, reading in 4KB chunks."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is private/reserved (RFC 1918, loopback, etc.)."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ThreatIntelResult:
    """Result from a single threat intel source for a file hash query."""

    source: str  # "virustotal", "threatbook", "cuckoo", "otx"
    malicious: int
    total: int
    suspicious: int = 0
    verdict: str = "unknown"  # malicious / suspicious / clean / unknown
    permalink: str | None = None
    scan_date: str | None = None
    details: dict = field(default_factory=dict)
    file_hash: str = ""


@dataclass(frozen=True)
class IOCItem:
    """A single IOC extracted from file content."""

    type: str  # "url", "domain", "ip", "hash"
    value: str
    source_file: str
    source_line: int


@dataclass(frozen=True)
class IOCIntelResult:
    """Result from a single threat intel source for an IOC query."""

    source: str
    ioc_type: str  # "url", "domain", "ip", "hash"
    ioc_value: str
    threat_level: str  # "high", "medium", "low", "info", "clean"
    tags: tuple[str, ...] = ()
    permalink: str | None = None
    details: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Backend protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class ThreatIntelBackend(Protocol):
    """Protocol that each threat intelligence backend must implement."""

    name: str
    supports_hash_lookup: bool
    supports_file_submission: bool
    supported_ioc_types: list[str]  # e.g. ["url", "domain", "ip", "hash"]

    def query_hash(self, file_hash: str) -> ThreatIntelResult | None:
        """Query the backend for a file hash.

        Returns None if hash not found or query fails.
        """
        ...

    def submit_file(self, file_path: Path, file_hash: str) -> ThreatIntelResult | None:
        """Submit a file for analysis (optional, only if supports_file_submission).

        Returns None if submission fails or not supported.
        """
        ...

    def query_ioc(self, ioc_type: str, ioc_value: str) -> IOCIntelResult | None:
        """Query the backend for an IOC (URL, domain, IP, or hash).

        Returns None if IOC not found or query fails.
        """
        ...
