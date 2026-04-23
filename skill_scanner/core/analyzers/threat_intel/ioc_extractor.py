"""
IOC (Indicator of Compromise) extractor for text and script files.

Extracts URLs, IP addresses, domains, and file hashes from skill content
(markdown, Python scripts, shell scripts, etc.) for threat intelligence lookups.
"""

from __future__ import annotations

import re
from typing import ClassVar

from .base import IOCItem, is_private_ip

# ---------------------------------------------------------------------------
# Extraction patterns
# ---------------------------------------------------------------------------

_URL_RE = re.compile(
    r'https?://[^\s<>"\')\]]+[^\s<>"\')\]\.,]',
    re.IGNORECASE,
)

_IPV4_RE = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)

# Simplified IPv6: matches common forms like 2001:db8::1, ::1, fe80::1%eth0
_IPV6_RE = re.compile(
    r'\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b'
    r'|\b::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{0,4}\b'
    r'|\b(?:[0-9a-fA-F]{1,4}:){1,6}:\b'
    r'|\b(?:[0-9a-fA-F]{1,4}:){1,5}:[0-9a-fA-F]{1,4}\b',
)

# Domain: at least one dot, TLD is 2+ alpha chars
_DOMAIN_RE = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)'
    r'+[a-zA-Z]{2,}\b'
)

# Hash patterns (must appear as standalone hex strings)
_MD5_RE = re.compile(r'\b[a-fA-F0-9]{32}\b')
_SHA1_RE = re.compile(r'\b[a-fA-F0-9]{40}\b')
_SHA256_RE = re.compile(r'\b[a-fA-F0-9]{64}\b')

# Known test / placeholder hashes to skip
_KNOWN_TEST_HASHES: frozenset[str] = frozenset({
    "d41d8cd98f00b204e9800998ecf8427e",  # MD5 of empty string
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # SHA1 of empty string
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # SHA256 of empty string
})


class IOCExtractor:
    """Extract IOCs (URLs, IPs, domains, hashes) from text content."""

    # Well-known safe domains that don't need threat intel lookups
    TRUSTED_DOMAINS: ClassVar[frozenset[str]] = frozenset({
        # Version control & package registries
        "github.com", "gitlab.com", "bitbucket.org",
        "pypi.org", "npmjs.com", "npm registry.npmjs.org",
        "crates.io", "rubygems.org", "maven.apache.org",
        # Documentation & learning
        "docs.python.org", "docs.rs", "developer.mozilla.org",
        "readthedocs.io", "stackoverflow.com", "stackexchange.com",
        "wikipedia.org", "w3.org",
        # AI / LLM providers
        "openai.com", "anthropic.com", "api.openai.com",
        "google.com", "cloud.google.com",
        "amazonaws.com", "microsoft.com", "azure.com",
        # Common safe sites
        "example.com", "example.org", "example.net",
        "localhost", "127.0.0.1",
    })

    # TLDs that are almost always false positives in code (variable names, etc.)
    FP_TLDS: ClassVar[frozenset[str]] = frozenset({
        ".py", ".js", ".ts", ".sh", ".rb", ".go", ".rs",
        ".json", ".yaml", ".yml", ".toml", ".xml", ".html",
        ".css", ".md", ".txt", ".log", ".cfg", ".ini",
        # Code attribute patterns (os.path, sys.exit, etc.)
        ".path", ".exit", ".join", ".split", ".format", ".encode",
        ".read", ".write", ".open", ".close", ".get", ".set",
        ".append", ".remove", ".update", ".values", ".keys",
        ".items", ".sort", ".strip", ".replace", ".lower", ".upper",
    })

    # Python / common code module prefixes that should NOT be treated as domains
    CODE_PREFIXES: ClassVar[frozenset[str]] = frozenset({
        # Python stdlib
        "os", "sys", "re", "io", "json", "yaml", "toml", "csv", "xml",
        "math", "random", "datetime", "time", "date", "logging", "hashlib",
        "pathlib", "shutil", "tempfile", "glob", "fnmatch", "stat",
        "collections", "itertools", "functools", "operator", "enum",
        "typing", "dataclasses", "abc", "copy", "pprint", "textwrap",
        "string", "struct", "codecs", "unicodedata",
        "threading", "multiprocessing", "subprocess", "asyncio",
        "socket", "http", "urllib", "requests", "httpx", "aiohttp",
        "socketserver", "email", "html", "xml", "webbrowser",
        "argparse", "optparse", "getopt", "configparser", "logging",
        "unittest", "pytest", "doctest", "pdb", "profile", "timeit",
        "trace", "warnings", "contextlib", "gc", "inspect", "dis",
        "importlib", "pkgutil", "modulefinder",
        "sqlite3", "dbm", "pickle", "shelve", "zlib", "gzip",
        "bz2", "lzma", "zipfile", "tarfile",
        "hashlib", "hmac", "secrets", "ssl",
        "base64", "binascii", "quopri", "uu",
        "ast", "token", "tokenize", "parser", "symtable",
        "signal", "mmap", "ctypes", "platform", "errno",
        "atexit", "traceback", "linecache", "types",
        "numpy", "np", "pandas", "pd", "tensorflow", "tf",
        "torch", "sklearn", "scipy", "matplotlib", "plt",
        "sqlalchemy", "django", "flask", "fastapi", "pydantic",
        "click", "typer", "rich", "tqdm",
        # Common variable names used as prefixes
        "self", "cls", "args", "kwargs", "env", "config", "app",
        "db", "api", "url", "host", "port", "user", "name", "type",
        "data", "result", "response", "request", "session", "client",
        "model", "view", "controller", "manager", "handler", "service",
        "market", "order", "trade", "price", "token", "account",
        "event", "task", "job", "queue", "cache", "store",
        "file", "dir", "path", "src", "dst", "tmp", "lib",
    })

    def extract(self, content: str, file_path: str) -> list[IOCItem]:
        """Extract all IOCs from content."""
        iocs: list[IOCItem] = []
        iocs.extend(self._extract_urls(content, file_path))
        iocs.extend(self._extract_ips(content, file_path))
        iocs.extend(self._extract_domains(content, file_path))
        iocs.extend(self._extract_hashes(content, file_path))
        return self._deduplicate(iocs)

    # ------------------------------------------------------------------
    # URL extraction
    # ------------------------------------------------------------------

    def _extract_urls(self, content: str, file_path: str) -> list[IOCItem]:
        results: list[IOCItem] = []
        for lineno, line in enumerate(content.splitlines(), start=1):
            for match in _URL_RE.finditer(line):
                url = match.group()
                # Skip URLs that are clearly local / placeholder
                if self._is_url_noise(url):
                    continue
                results.append(IOCItem(
                    type="url",
                    value=url,
                    source_file=file_path,
                    source_line=lineno,
                ))
        return results

    @staticmethod
    def _is_url_noise(url: str) -> bool:
        """Filter out URLs that are clearly not threat-relevant."""
        lower = url.lower()
        # Local / internal URLs
        if lower.startswith(("http://localhost", "http://127.0.0.1", "http://0.0.0.0")):
            return True
        if lower.startswith(("https://localhost", "https://127.0.0.1")):
            return True
        # Placeholder URLs in documentation
        if "example.com" in lower or "example.org" in lower:
            return True
        if "your-domain" in lower or "your-api-key" in lower:
            return True
        return False

    # ------------------------------------------------------------------
    # IP extraction
    # ------------------------------------------------------------------

    def _extract_ips(self, content: str, file_path: str) -> list[IOCItem]:
        results: list[IOCItem] = []
        seen: set[str] = set()
        for lineno, line in enumerate(content.splitlines(), start=1):
            for match in _IPV4_RE.finditer(line):
                ip = match.group()
                if ip in seen:
                    continue
                if is_private_ip(ip):
                    continue
                # Skip common false positives in code
                if self._is_ip_context_noise(line, match.start()):
                    continue
                seen.add(ip)
                results.append(IOCItem(
                    type="ip",
                    value=ip,
                    source_file=file_path,
                    source_line=lineno,
                ))
        return results

    @staticmethod
    def _is_ip_context_noise(line: str, pos: int) -> bool:
        """Check if the IP match is inside a context that makes it noise."""
        # Version strings like "3.10.0" should not match IPs
        # Check for surrounding digits that suggest a version number
        start = max(0, pos - 2)
        end = min(len(line), pos + 20)
        context = line[start:end]
        # Patterns like x.y.z.w where more dots follow suggest version numbers
        if re.match(r'\d+\.\d+\.\d+\.\d+\.\d+', context):
            return True
        return False

    # ------------------------------------------------------------------
    # Domain extraction
    # ------------------------------------------------------------------

    def _extract_domains(self, content: str, file_path: str) -> list[IOCItem]:
        results: list[IOCItem] = []
        seen: set[str] = set()
        for lineno, line in enumerate(content.splitlines(), start=1):
            # Skip lines that are inside code comments or string definitions
            # of safe patterns
            for match in _DOMAIN_RE.finditer(line):
                domain = match.group().lower()
                if domain in seen:
                    continue
                if self._is_domain_noise(domain, line):
                    continue
                seen.add(domain)
                results.append(IOCItem(
                    type="domain",
                    value=domain,
                    source_file=file_path,
                    source_line=lineno,
                ))
        return results

    def _is_domain_noise(self, domain: str, line: str) -> bool:
        """Filter out domains that are false positives."""
        # Trusted domains
        if domain in self.TRUSTED_DOMAINS:
            return True
        # Check if any segment or TLD matches known false-positive patterns
        for tld in self.FP_TLDS:
            if domain.endswith(tld):
                return True
            # Also check intermediate segments (e.g., "os.path.exists" matches ".path")
            if f".{tld.lstrip('.')}" in f".{domain}":
                return True
        # Check if first segment is a known code module/variable prefix
        parts = domain.split(".")
        if parts[0].lower() in self.CODE_PREFIXES:
            return True
        # Multi-level domains where any non-TLD segment is a code prefix
        # e.g., "args.category.title" → args is a code prefix
        for part in parts[:-1]:  # Skip last part (could be a valid TLD)
            if part.lower() in self.CODE_PREFIXES:
                return True
        # Skip domains inside markdown link definitions that are clearly safe
        if "](http" in line and domain in self.TRUSTED_DOMAINS:
            return True
        return False

    # ------------------------------------------------------------------
    # Hash extraction
    # ------------------------------------------------------------------

    def _extract_hashes(self, content: str, file_path: str) -> list[IOCItem]:
        results: list[IOCItem] = []
        seen: set[str] = set()
        for lineno, line in enumerate(content.splitlines(), start=1):
            # Check SHA256 first (longest), then SHA1, then MD5
            for match in _SHA256_RE.finditer(line):
                h = match.group().lower()
                if h in seen or h in _KNOWN_TEST_HASHES:
                    continue
                if self._is_hash_context_noise(line, match.start()):
                    continue
                seen.add(h)
                results.append(IOCItem(type="hash", value=h, source_file=file_path, source_line=lineno))

            for match in _SHA1_RE.finditer(line):
                h = match.group().lower()
                if h in seen or h in _KNOWN_TEST_HASHES:
                    continue
                if self._is_hash_context_noise(line, match.start()):
                    continue
                seen.add(h)
                results.append(IOCItem(type="hash", value=h, source_file=file_path, source_line=lineno))

            for match in _MD5_RE.finditer(line):
                h = match.group().lower()
                if h in seen or h in _KNOWN_TEST_HASHES:
                    continue
                if self._is_hash_context_noise(line, match.start()):
                    continue
                seen.add(h)
                results.append(IOCItem(type="hash", value=h, source_file=file_path, source_line=lineno))
        return results

    @staticmethod
    def _is_hash_context_noise(line: str, pos: int) -> bool:
        """Check if hash match is inside a noisy context."""
        # Skip hashes that are clearly hex color codes (# prefix)
        if pos > 0 and line[pos - 1] == "#":
            return True
        # Skip if this is a git commit hash context
        lower = line.lower()
        if "commit" in lower or "sha:" in lower or "sha =" in lower:
            # But DO allow it if it's explicitly labeled as a file hash
            if "file" not in lower and "malware" not in lower and "sample" not in lower:
                return True
        return False

    # ------------------------------------------------------------------
    # Deduplication
    # ------------------------------------------------------------------

    @staticmethod
    def _deduplicate(iocs: list[IOCItem]) -> list[IOCItem]:
        """Remove duplicate IOCs (same type + value), keeping first occurrence."""
        seen: set[tuple[str, str]] = set()
        result: list[IOCItem] = []
        for ioc in iocs:
            key = (ioc.type, ioc.value)
            if key not in seen:
                seen.add(key)
                result.append(ioc)
        return result
