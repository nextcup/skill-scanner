"""
Unified threat intelligence analyzer with pluggable backends.

Supports multiple threat intel sources (VirusTotal, ThreatBook, Cuckoo, OTX)
for both binary file hash lookups and IOC (URL/Domain/IP/Hash) queries
extracted from markdown and script files.
"""

from .base import (
    IOCIntelResult,
    IOCItem,
    ThreatIntelBackend,
    ThreatIntelResult,
)
from .ioc_extractor import IOCExtractor
from .threat_intel_analyzer import ThreatIntelAnalyzer

__all__ = [
    "IOCExtractor",
    "IOCIntelResult",
    "IOCItem",
    "ThreatIntelAnalyzer",
    "ThreatIntelBackend",
    "ThreatIntelResult",
]
