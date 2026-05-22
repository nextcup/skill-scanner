# Copyright 2026 Cisco Systems, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""API router for Skill Scanner endpoints.

This router provides the same functionality as ``api_server.py`` but in a
composable ``APIRouter`` form, allowing it to be mounted in other FastAPI
applications.  All parameters and behaviour mirror the standalone server for
full CLI/API parity.
"""

import logging
import os
import pickle
import shutil
import tempfile
import threading
import time
import uuid
from collections import OrderedDict
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

try:
    from fastapi import APIRouter, BackgroundTasks, File, Form, Header, HTTPException, UploadFile
    from pydantic import BaseModel, Field

    MULTIPART_AVAILABLE = True
except ImportError:
    raise ImportError("API server requires FastAPI. Install with: pip install fastapi uvicorn python-multipart")

import os

from .. import __version__ as PACKAGE_VERSION
from ..core.analyzer_factory import build_analyzers
from ..core.exceptions import SkillLoadError
from ..core.scan_policy import ScanPolicy
from ..core.scanner import SkillScanner

logger = logging.getLogger("skill_scanner.api")

LLMAnalyzer: type | None
try:
    from ..core.analyzers.llm_analyzer import LLMAnalyzer

    LLM_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    LLM_AVAILABLE = False
    LLMAnalyzer = None

BehavioralAnalyzer: type | None
try:
    from ..core.analyzers.behavioral_analyzer import BehavioralAnalyzer

    BEHAVIORAL_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    BEHAVIORAL_AVAILABLE = False
    BehavioralAnalyzer = None

AIDefenseAnalyzer: type | None
try:
    from ..core.analyzers.aidefense_analyzer import AIDefenseAnalyzer

    AIDEFENSE_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    AIDEFENSE_AVAILABLE = False
    AIDefenseAnalyzer = None

VirusTotalAnalyzer: type | None
try:
    from ..core.analyzers.virustotal_analyzer import VirusTotalAnalyzer

    VIRUSTOTAL_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    VIRUSTOTAL_AVAILABLE = False
    VirusTotalAnalyzer = None

TriggerAnalyzer: type | None
try:
    from ..core.analyzers.trigger_analyzer import TriggerAnalyzer

    TRIGGER_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    TRIGGER_AVAILABLE = False
    TriggerAnalyzer = None

MetaAnalyzer: type | None
apply_meta_analysis_to_results: Callable[..., list] | None
try:
    from ..core.analyzers.meta_analyzer import MetaAnalyzer, apply_meta_analysis_to_results

    META_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    META_AVAILABLE = False
    MetaAnalyzer = None
    apply_meta_analysis_to_results = None

router = APIRouter()

# ---------------------------------------------------------------------------
# Upload & cache safety limits
# ---------------------------------------------------------------------------

MAX_UPLOAD_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB max upload
MAX_ZIP_ENTRIES = 500  # max files extracted from uploaded ZIP
MAX_ZIP_UNCOMPRESSED_BYTES = 200 * 1024 * 1024  # 200 MB uncompressed limit
MAX_CACHE_ENTRIES = 1_000  # evict oldest when exceeded
CACHE_TTL_SECONDS = 3600  # 1 hour
CACHE_DIR = Path(tempfile.gettempdir()) / "skill_scanner_cache"  # Shared cache directory


def _ensure_cache_dir():
    """Ensure cache directory exists."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)


def _extract_zip_with_security(
    zip_path: Path,
    extract_root: Path,
    zip_password: str | None = None,
) -> None:
    """安全地解压ZIP文件，执行所有必要的安全检查（防止TOCTOU竞态条件）.

    安全策略：
    1. 使用临时目录先解压，验证后再移动
    2. 使用受限 umask 确保新文件权限受限
    3. 在移动前验证所有文件（无符号链接、无路径遍历）
    4. 验证通过后设置只读权限再移动

    Args:
        zip_path: ZIP文件路径
        extract_root: 解压目标目录
        zip_password: 可选的ZIP密码

    Raises:
        HTTPException: 对于各种安全/验证错误
        ValueError: 对于ZIP格式错误
    """
    import os
    import stat
    import tempfile
    import zipfile

    try:
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            # 验证条目数量和解压大小
            entries = [info for info in zip_ref.infolist() if not info.is_dir()]
            if len(entries) > MAX_ZIP_ENTRIES:
                raise ValueError(f"ZIP contains {len(entries)} files, exceeding limit of {MAX_ZIP_ENTRIES}")
            total_uncompressed = sum(info.file_size for info in entries)
            if total_uncompressed > MAX_ZIP_UNCOMPRESSED_BYTES:
                raise ValueError(
                    f"ZIP uncompressed size ({total_uncompressed // (1024 * 1024)} MB) "
                    f"exceeds limit of {MAX_ZIP_UNCOMPRESSED_BYTES // (1024 * 1024)} MB"
                )

            # 预检查：ZIP元数据中的符号链接和路径遍历
            for info in zip_ref.infolist():
                unix_mode = (info.external_attr >> 16) & 0xFFFF
                if unix_mode != 0 and stat.S_ISLNK(unix_mode):
                    raise HTTPException(
                        status_code=400,
                        detail="ZIP contains symbolic link entries"
                    )
                # 检查路径遍历（在解压前）
                dest_path = (extract_root / info.filename).resolve()
                if not dest_path.is_relative_to(extract_root):
                    raise HTTPException(
                        status_code=400,
                        detail="ZIP contains path traversal entries"
                    )

            # 保存当前 umask 并设置受限权限（只有所有者可访问）
            old_umask = os.umask(0o077)

            try:
                # 创建目标目录
                extract_root.mkdir(parents=True, exist_ok=True)

                # 使用临时目录进行解压（与目标目录同父级）
                with tempfile.TemporaryDirectory(dir=extract_root.parent, prefix="skill_scan_") as temp_extract:
                    # 阶段1：解压到临时目录
                    for info in zip_ref.infolist():
                        if zip_password:
                            zip_ref.extract(info, temp_extract, pwd=zip_password.encode('utf-8'))
                        else:
                            zip_ref.extract(info, temp_extract)

                    # 阶段2：验证解压后的文件
                    temp_extract_path = Path(temp_extract)
                    for extracted_file in temp_extract_path.rglob("*"):
                        # 拒绝任何符号链接
                        if extracted_file.is_symlink():
                            raise HTTPException(
                                status_code=400,
                                detail="ZIP extraction produced a symbolic link — rejected"
                            )

                        # 设置为只读权限（在移动前）
                        if extracted_file.is_file():
                            extracted_file.chmod(0o444)

                    # 阶段3：验证通过后，原子性地移动到目标位置
                    for item in temp_extract_path.iterdir():
                        target = extract_root / item.name
                        if target.exists():
                            # 如果目标已存在，先删除
                            if target.is_dir():
                                import shutil
                                shutil.rmtree(target, ignore_errors=True)
                            else:
                                target.unlink()
                        import shutil
                        shutil.move(str(item), str(target))

            finally:
                # 恢复原始 umask
                os.umask(old_umask)

    except zipfile.BadZipFile as e:
        error_msg = _redact_password(str(e), zip_password)
        if "password required" in error_msg.lower() or "bad password" in error_msg.lower():
            if not zip_password:
                raise HTTPException(
                    status_code=400,
                    detail="ZIP_ENCRYPTED: ZIP file is encrypted. Please provide the password using the 'zip_password' parameter."
                ) from e
            else:
                raise HTTPException(
                    status_code=401,
                    detail="ZIP_DECRYPTION_FAILED: Incorrect password for encrypted ZIP file."
                ) from e
        raise HTTPException(
            status_code=400,
            detail=f"ZIP_FORMAT_ERROR: Invalid ZIP archive - {error_msg}"
        ) from e
    except RuntimeError as e:
        error_msg = _redact_password(str(e), zip_password)
        if "password required" in error_msg.lower():
            if not zip_password:
                raise HTTPException(
                    status_code=400,
                    detail="ZIP_ENCRYPTED: ZIP file is encrypted. Please provide the password using the 'zip_password' parameter."
                ) from e
            else:
                raise HTTPException(
                    status_code=401,
                    detail="ZIP_DECRYPTION_FAILED: Incorrect password for encrypted ZIP file."
                ) from e
        raise


_ensure_cache_dir()


# File-based cache for async scans - shares state across workers.
# Each scan_id gets its own file under CACHE_DIR.
class _FileBasedCache:
    """File-based cache with TTL - shares state across Gunicorn workers."""

    def __init__(self):
        self._lock = threading.Lock()

    def _get_cache_file(self, key: str) -> Path:
        return CACHE_DIR / f"{key}.cache"

    def set(self, key: str, value: dict) -> None:
        with self._lock:
            value["_cached_at"] = time.monotonic()
            cache_file = self._get_cache_file(key)

            # Write to temporary file first, then rename (atomic operation)
            temp_file = cache_file.with_suffix(".tmp")
            try:
                with open(temp_file, "wb") as f:
                    pickle.dump(value, f)
                temp_file.replace(cache_file)

                # Clean up old entries if exceeding limit
                self._cleanup_old_entries()
            except Exception as e:
                logger.error(f"Failed to write cache file {cache_file}: {e}")
                if temp_file.exists():
                    temp_file.unlink()

    def get_valid(self, key: str) -> dict | None:
        with self._lock:
            cache_file = self._get_cache_file(key)

            if not cache_file.exists():
                return None

            try:
                with open(cache_file, "rb") as f:
                    entry = pickle.load(f)

                # Check TTL
                if time.monotonic() - entry.get("_cached_at", 0) > CACHE_TTL_SECONDS:
                    cache_file.unlink(missing_ok=True)
                    return None

                result: dict = entry
                return result

            except Exception as e:
                logger.error(f"Failed to read cache file {cache_file}: {e}")
                # Clean up corrupted file
                cache_file.unlink(missing_ok=True)
                return None

    def _cleanup_old_entries(self):
        """Remove oldest cache entries if exceeding MAX_CACHE_ENTRIES."""
        try:
            cache_files = list(CACHE_DIR.glob("*.cache"))
            if len(cache_files) > MAX_CACHE_ENTRIES:
                # Sort by modification time and remove oldest
                cache_files.sort(key=lambda p: p.stat().st_mtime)
                for old_file in cache_files[: (len(cache_files) - MAX_CACHE_ENTRIES)]:
                    old_file.unlink(missing_ok=True)
        except Exception as e:
            logger.warning(f"Failed to cleanup old cache entries: {e}")


# Use file-based cache to support multi-worker deployments
scan_results_cache = _FileBasedCache()

# Environment-configurable allowlist of directories the API may access.
# When empty (default) any *resolved* absolute path is accepted — operators
# should set SKILL_SCANNER_ALLOWED_ROOTS to restrict access in production.
_ALLOWED_ROOTS: list[Path] = [
    Path(p).resolve() for p in os.environ.get("SKILL_SCANNER_ALLOWED_ROOTS", "").split(":") if p.strip()
]


def _validate_path(user_input: str, *, label: str = "path") -> Path:
    """Sanitize and validate a user-supplied filesystem path.

    Rejects null bytes and path-traversal attempts, resolves symlinks, and
    enforces the optional SKILL_SCANNER_ALLOWED_ROOTS allowlist.
    """
    if "\x00" in user_input:
        raise HTTPException(status_code=400, detail=f"Invalid {label}: null bytes are not allowed")

    resolved = Path(user_input).resolve()

    if _ALLOWED_ROOTS and not any(resolved == root or resolved.is_relative_to(root) for root in _ALLOWED_ROOTS):
        raise HTTPException(
            status_code=403,
            detail=f"Access denied: {label} is outside the allowed directories",
        )

    return resolved


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    """Request model for scanning a skill."""

    skill_directory: str = Field(..., description="Path to skill directory")
    policy: str | None = Field(
        None,
        description="Scan policy: preset name (strict, balanced, permissive) or path to custom YAML",
    )
    custom_rules: str | None = Field(None, description="Path to custom YARA rules directory")
    use_llm: bool = Field(False, description="Enable LLM analyzer")
    llm_provider: str | None = Field("anthropic", description="LLM provider (anthropic or openai)")
    use_behavioral: bool = Field(False, description="Enable behavioral analyzer")
    use_virustotal: bool = Field(False, description="Enable VirusTotal binary file scanning")
    vt_upload_files: bool = Field(False, description="Upload unknown files to VirusTotal")
    use_aidefense: bool = Field(False, description="Enable AI Defense analyzer")
    aidefense_api_url: str | None = Field(None, description="AI Defense API URL")
    use_trigger: bool = Field(False, description="Enable trigger specificity analysis")
    enable_meta: bool = Field(False, description="Enable meta-analysis for false positive filtering")
    llm_consensus_runs: int = Field(1, description="Number of LLM consensus runs (majority vote)")
    strict_mode: bool = Field(False, description="Enable strict validation (fail on missing SKILL.md fields). Default is lenient mode.")


# Meta-analysis response models for Swagger documentation
class MetaAnalysisStatistics(BaseModel):
    """Statistics of findings by threat category."""

    prompt_injection: int = 0
    command_injection: int = 0
    data_exfiltration: int = 0
    unauthorized_tool_use: int = 0
    obfuscation: int = 0
    hardcoded_secrets: int = 0
    social_engineering: int = 0
    resource_abuse: int = 0
    policy_violation: int = 0
    malware: int = 0
    harmful_content: int = 0
    skill_discovery_abuse: int = 0
    transitive_trust_abuse: int = 0
    autonomy_abuse: int = 0
    tool_chaining_abuse: int = 0
    unicode_steganography: int = 0
    supply_chain_attack: int = 0
    credential_theft: int = 0


class MetaAnalysisSummary(BaseModel):
    """Summary of meta-analysis results."""

    total_original: int
    validated_count: int
    false_positive_count: int
    missed_threats_count: int
    recommendations_count: int
    statistics: MetaAnalysisStatistics
    llm_primary_threats: list[str]


class MetaAnalysisResponse(BaseModel):
    """Meta-analysis results."""

    validated_findings: list[dict]
    false_positives: list[dict]
    missed_threats: list[dict]
    priority_order: list[int]
    correlations: list[dict]
    recommendations: list[dict]
    overall_risk_assessment: dict
    summary: MetaAnalysisSummary


class ScanResponse(BaseModel):
    """Response model for scan results."""

    scan_id: str
    skill_name: str
    is_safe: bool
    max_severity: str
    findings_count: int
    scan_duration_seconds: float
    timestamp: str
    findings: list[dict]
    meta_analysis: MetaAnalysisResponse | None = Field(
        None,
        description="Meta-analysis results if enabled. Contains validated findings, false positives, correlations, recommendations, and summary statistics.",
    )


class HealthResponse(BaseModel):
    """Health check response."""

    status: str
    version: str
    analyzers_available: list[str]


class BatchScanRequest(BaseModel):
    """Request for batch scanning."""

    skills_directory: str
    policy: str | None = Field(
        None,
        description="Scan policy: preset name (strict, balanced, permissive) or path to custom YAML",
    )
    custom_rules: str | None = Field(None, description="Path to custom YARA rules directory")
    recursive: bool = False
    check_overlap: bool = Field(False, description="Enable cross-skill description overlap detection")
    use_llm: bool = False
    llm_provider: str | None = "anthropic"
    use_behavioral: bool = False
    use_virustotal: bool = False
    vt_upload_files: bool = False
    use_aidefense: bool = False
    aidefense_api_url: str | None = None
    use_trigger: bool = False
    enable_meta: bool = Field(False, description="Enable meta-analysis")
    llm_consensus_runs: int = Field(1, description="Number of LLM consensus runs (majority vote)")
    strict_mode: bool = Field(False, description="Enable strict validation (fail on missing SKILL.md fields). Default is lenient mode.")


# ---------------------------------------------------------------------------
# Error categorization
# ---------------------------------------------------------------------------


def _redact_password(message: str, password: str | None) -> str:
    """从消息中脱敏密码（使用正则表达式进行大小写不敏感替换）.

    Args:
        message: 可能包含密码的消息
        password: 需要脱敏的密码

    Returns:
        脱敏后的消息

    Note:
        使用正则表达式避免简单字符串替换被绕过，并处理大小写变化。
    """
    if not password:
        return message

    import re

    try:
        # 转义特殊正则字符，进行大小写不敏感替换
        escaped = re.escape(password)
        return re.sub(escaped, "***REDACTED***", message, flags=re.IGNORECASE)
    except re.error:
        # 如果正则转义失败，回退到简单替换
        return message.replace(password, "***REDACTED***")


def _validate_zip_password(zip_password: str | None) -> None:
    """验证 ZIP 密码参数.

    Args:
        zip_password: ZIP 密码

    Raises:
        HTTPException: 如果密码验证失败
    """
    if zip_password is not None:
        if not isinstance(zip_password, str):
            raise HTTPException(
                status_code=400,
                detail="ZIP_PASSWORD_VALIDATION_ERROR: Password must be a string."
            )
        if not zip_password:
            raise HTTPException(
                status_code=400,
                detail="ZIP_PASSWORD_VALIDATION_ERROR: Password cannot be empty string."
            )
        if len(zip_password) > 128:
            raise HTTPException(
                status_code=400,
                detail="ZIP_PASSWORD_VALIDATION_ERROR: Password too long (max 128 characters)."
            )


# 错误类别到HTTP状态码的映射
_ERROR_STATUS_MAPPING: dict[str, int] = {
    # Client errors (4xx)
    "SKILL_MD_FORMAT_ERROR": 400,
    "SKILL_MD_NOT_FOUND": 400,
    "SKILL_MD_LOAD_ERROR": 400,
    "FILE_ENCODING_ERROR": 400,
    "FILE_SIZE_ERROR": 413,  # Payload Too Large
    "FILE_TYPE_ERROR": 415,  # Unsupported Media Type
    "POLICY_CONFIG_ERROR": 400,
    "POLICY_PARSE_ERROR": 400,
    "POLICY_ERROR": 400,
    "YARA_RULE_ERROR": 400,
    "CUSTOM_RULES_ERROR": 400,
    "ZIP_ENCRYPTED": 400,
    "ZIP_DECRYPTION_FAILED": 401,  # Unauthorized (wrong password)
    "ZIP_PASSWORD_VALIDATION_ERROR": 400,
    "FILE_NOT_FOUND": 404,
    "PERMISSION_ERROR": 403,  # Forbidden
    "FILESYSTEM_ERROR": 500,
    # LLM errors
    "LLM_AUTH_ERROR": 500,  # Server configuration issue
    "LLM_TIMEOUT_ERROR": 504,  # Gateway Timeout
    "LLM_RATE_LIMIT_ERROR": 429,  # Too Many Requests
    "LLM_NETWORK_ERROR": 503,  # Service Unavailable
    "LLM_ERROR": 500,
    # AI Defense errors
    "AIDEFENSE_CONFIG_ERROR": 500,
    "AIDEFENSE_AUTH_ERROR": 500,
    "AIDEFENSE_TIMEOUT_ERROR": 504,
    "AIDEFENSE_ERROR": 500,
    # VirusTotal errors
    "VIRUSTOTAL_AUTH_ERROR": 500,
    "VIRUSTOTAL_NETWORK_ERROR": 503,
    "VIRUSTOTAL_ERROR": 500,
    # Unknown
    "UNKNOWN_ERROR": 500,
}


def _get_error_status_code(category: str) -> int:
    """获取错误类别对应的HTTP状态码.

    Args:
        category: 错误类别

    Returns:
        HTTP状态码
    """
    return _ERROR_STATUS_MAPPING.get(category, 500)


def _categorize_error(error: Exception) -> tuple[str, str]:
    """将异常分类为 (问题类别, 错误原因) 元组.

    Returns:
        Tuple of (category, detailed_reason)
    """
    error_msg = str(error)
    error_type = type(error).__name__

    # SKILL.md 格式错误
    if isinstance(error, SkillLoadError):
        if "missing required field: name" in error_msg.lower():
            return "SKILL_MD_FORMAT_ERROR", "SKILL.md 缺少必需的 name 字段"
        if "missing required field: description" in error_msg.lower():
            return "SKILL_MD_FORMAT_ERROR", "SKILL.md 缺少必需的 description 字段"
        if "yaml frontmatter" in error_msg.lower():
            return "SKILL_MD_FORMAT_ERROR", f"YAML frontmatter 解析失败: {error_msg}"
        if "not found" in error_msg.lower() and "skill.md" in error_msg.lower():
            return "SKILL_MD_NOT_FOUND", "SKILL.md 文件不存在"
        if "null byte" in error_msg.lower():
            return "FILE_ENCODING_ERROR", "文件包含空字节，可能为二进制文件"
        if "utf-8" in error_msg.lower() or "encoding" in error_msg.lower():
            return "FILE_ENCODING_ERROR", "文件编码错误，需要 UTF-8 格式"
        if "lenient mode" in error_msg.lower() and ".md file" in error_msg.lower():
            return "SKILL_MD_NOT_FOUND", "没有找到 SKILL.md 或任何 .md 文件（lenient 模式）"
        return "SKILL_LOAD_ERROR", error_msg

    # 策略配置错误
    if "policy" in error_msg.lower() or "策略" in error_msg:
        if "unknown policy" in error_msg.lower():
            return "POLICY_CONFIG_ERROR", f"未知的策略名称: {error_msg}"
        if "not a file" in error_msg.lower():
            return "POLICY_CONFIG_ERROR", "策略路径不是文件"
        if "must have a .yaml or .yml extension" in error_msg.lower():
            return "POLICY_CONFIG_ERROR", "策略文件必须是 .yaml 或 .yml 格式"
        if "yaml" in error_msg.lower():
            return "POLICY_PARSE_ERROR", f"策略 YAML 解析失败: {error_msg}"
        return "POLICY_ERROR", error_msg

    # LLM API 错误
    if "llm" in error_msg.lower() or "anthropic" in error_msg.lower() or "openai" in error_msg.lower():
        if "api key" in error_msg.lower() or "authentication" in error_msg.lower():
            return "LLM_AUTH_ERROR", "LLM API 认证失败，请检查 API key 配置"
        if "timeout" in error_msg.lower():
            return "LLM_TIMEOUT_ERROR", "LLM API 请求超时"
        if "rate limit" in error_msg.lower() or "quota" in error_msg.lower() or "429" in error_msg:
            return "LLM_RATE_LIMIT_ERROR", "LLM API 配额用尽或触发速率限制"
        if "connection" in error_msg.lower() or "network" in error_msg.lower():
            return "LLM_NETWORK_ERROR", "LLM API 网络连接失败"
        return "LLM_ERROR", error_msg

    # AI Defense 错误
    if "aidefense" in error_msg.lower() or "ai defense" in error_msg.lower():
        if "api url" in error_msg.lower() or "endpoint" in error_msg.lower():
            return "AIDEFENSE_CONFIG_ERROR", "AI Defense API URL 配置错误"
        if "authentication" in error_msg.lower() or "unauthorized" in error_msg.lower() or "401" in error_msg:
            return "AIDEFENSE_AUTH_ERROR", "AI Defense 认证失败"
        if "timeout" in error_msg.lower():
            return "AIDEFENSE_TIMEOUT_ERROR", "AI Defense API 请求超时"
        return "AIDEFENSE_ERROR", error_msg

    # VirusTotal 错误
    if "virustotal" in error_msg.lower() or "vt_" in error_msg.lower():
        if "api key" in error_msg.lower():
            return "VIRUSTOTAL_AUTH_ERROR", "VirusTotal API key 无效"
        if "network" in error_msg.lower() or "connection" in error_msg.lower():
            return "VIRUSTOTAL_NETWORK_ERROR", "VirusTotal 网络连接失败"
        return "VIRUSTOTAL_ERROR", error_msg

    # 文件大小/类型错误
    if "file size" in error_msg.lower() or "too large" in error_msg.lower():
        return "FILE_SIZE_ERROR", f"文件大小超过限制: {error_msg}"
    if "binary" in error_msg.lower():
        return "FILE_TYPE_ERROR", "不支持的二进制文件类型"
    if "null byte" in error_msg.lower():
        return "FILE_ENCODING_ERROR", "文件包含空字节，可能为二进制文件"
    if "encoding" in error_msg.lower() or "utf-8" in error_msg.lower():
        return "FILE_ENCODING_ERROR", "文件编码错误，需要 UTF-8 格式"

    # 自定义规则错误
    if "yara" in error_msg.lower():
        return "YARA_RULE_ERROR", f"YARA 规则错误: {error_msg}"
    if "custom rules" in error_msg.lower() or "custom_rules" in error_msg.lower():
        return "CUSTOM_RULES_ERROR", error_msg

    # 文件系统错误
    if error_type in ("FileNotFoundError", "PermissionError", "OSError"):
        if "not found" in error_msg.lower():
            return "FILE_NOT_FOUND", error_msg
        if "permission" in error_msg.lower():
            return "PERMISSION_ERROR", "文件系统权限不足"
        return "FILESYSTEM_ERROR", error_msg

    # 未知错误
    return "UNKNOWN_ERROR", f"{error_type}: {error_msg}"


def _sanitize_stack_trace(stack: str) -> str:
    """清理堆栈跟踪中的敏感信息（绝对路径、用户信息等）.

    Args:
        stack: 原始堆栈跟踪字符串

    Returns:
        清理后的堆栈跟踪字符串
    """
    import re

    # 移除用户主路径信息
    home = os.path.expanduser("~")
    sanitized = stack
    if home in sanitized:
        sanitized = sanitized.replace(home, "~")

    # 移除 Windows 绝对路径（如 C:\Users\user\project\file.py）
    # 保留最后两段路径
    sanitized = re.sub(
        r'File "[A-Z]:\\(?:[^\\]+\\)*([^\\]+\\[^\\]+\.py)"',
        r'File "\1"',
        sanitized
    )

    # 移除 Unix 绝对路径（如 /home/user/project/file.py）
    # 保留最后两段路径
    sanitized = re.sub(
        r'File "/(?:[^/]+/)*([^/]+/[^/]+\.py)"',
        r'File "\1"',
        sanitized
    )

    return sanitized


def _build_error_detail(category: str, reason: str, debug_mode: bool = False) -> str:
    """构建结构化的错误详情.

    Args:
        category: 问题类别
        reason: 错误原因
        debug_mode: 是否在调试模式下返回完整堆栈

    Returns:
        格式化的错误详情字符串

    Security Note:
        调试模式会暴露堆栈跟踪信息，应仅在受信任的环境中使用。
        生产环境中应设置 DEBUG=false 并通过环境变量控制访问。
    """
    if debug_mode:
        import traceback

        stack = "".join(traceback.format_stack()[-3:-1]).strip()
        # 清理堆栈跟踪中的敏感信息
        sanitized_stack = _sanitize_stack_trace(stack)
        return f"{category}: {reason}\n\nStack trace:\n{sanitized_stack}"
    return f"{category}: {reason}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _resolve_policy(policy_str: str | None) -> ScanPolicy:
    """Resolve a policy string to a ScanPolicy object."""
    if policy_str is None or not policy_str.strip():
        return ScanPolicy.default()
    policy_str = policy_str.strip()
    if policy_str.lower() in ("strict", "balanced", "permissive"):
        return ScanPolicy.from_preset(policy_str)
    policy_path = _validate_path(policy_str, label="policy path")
    if policy_path.exists():
        if not policy_path.is_file():
            raise ValueError(f"Policy path '{policy_str}' is not a file.")
        if policy_path.suffix not in (".yaml", ".yml"):
            raise ValueError("Policy file must have a .yaml or .yml extension.")
        return ScanPolicy.from_yaml(str(policy_path))
    raise ValueError(f"Unknown policy '{policy_str}'. Use a preset name or a path to a YAML file.")


def _build_analyzers(
    policy: ScanPolicy,
    *,
    custom_rules: str | None = None,
    use_behavioral: bool = False,
    use_llm: bool = False,
    llm_provider: str | None = "anthropic",
    use_virustotal: bool = False,
    vt_api_key: str | None = None,
    vt_upload_files: bool = False,
    use_aidefense: bool = False,
    aidefense_api_key: str | None = None,
    aidefense_api_url: str | None = None,
    use_trigger: bool = False,
    llm_consensus_runs: int = 1,
):
    """Build the analyzer list — delegates to the centralized factory."""
    return build_analyzers(
        policy,
        custom_yara_rules_path=custom_rules,
        use_behavioral=use_behavioral,
        use_llm=use_llm,
        llm_provider=llm_provider,
        use_virustotal=use_virustotal,
        vt_api_key=vt_api_key,
        vt_upload_files=vt_upload_files,
        use_aidefense=use_aidefense,
        aidefense_api_key=aidefense_api_key,
        aidefense_api_url=aidefense_api_url,
        use_trigger=use_trigger,
        llm_consensus_runs=llm_consensus_runs,
    )


def _recompute_report_summary(report) -> None:
    """Recompute Report aggregate counters from current per-skill findings."""
    report.total_skills_scanned = len(report.scan_results)
    report.total_findings = sum(len(r.findings) for r in report.scan_results)
    report.critical_count = 0
    report.high_count = 0
    report.medium_count = 0
    report.low_count = 0
    report.info_count = 0
    report.safe_count = sum(1 for r in report.scan_results if r.is_safe)

    all_findings = [f for r in report.scan_results for f in r.findings]
    cross = getattr(report, "cross_skill_findings", None) or []
    report.total_findings += len(cross)
    all_findings.extend(cross)

    for finding in all_findings:
        sev = getattr(finding.severity, "value", str(finding.severity)).upper()
        if sev == "CRITICAL":
            report.critical_count += 1
        elif sev == "HIGH":
            report.high_count += 1
        elif sev == "MEDIUM":
            report.medium_count += 1
        elif sev == "LOW":
            report.low_count += 1
        elif sev == "INFO":
            report.info_count += 1


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/", response_model=dict)
async def root():
    """Root endpoint."""
    return {"service": "Skill Scanner API", "version": PACKAGE_VERSION, "docs": "/docs", "health": "/health"}


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    analyzers = ["static_analyzer", "bytecode_analyzer", "pipeline_analyzer"]
    if BEHAVIORAL_AVAILABLE:
        analyzers.append("behavioral_analyzer")
    if LLM_AVAILABLE:
        analyzers.append("llm_analyzer")
    if VIRUSTOTAL_AVAILABLE:
        analyzers.append("virustotal_analyzer")
    if AIDEFENSE_AVAILABLE:
        analyzers.append("aidefense_analyzer")
    if TRIGGER_AVAILABLE:
        analyzers.append("trigger_analyzer")
    if META_AVAILABLE:
        analyzers.append("meta_analyzer")

    return HealthResponse(status="healthy", version=PACKAGE_VERSION, analyzers_available=analyzers)


@router.post("/scan", response_model=ScanResponse)
async def scan_skill(
    request: ScanRequest,
    vt_api_key: str | None = Header(None, alias="X-VirusTotal-Key"),
    aidefense_api_key: str | None = Header(None, alias="X-AIDefense-Key"),
):
    """Scan a single skill package."""
    import asyncio
    import concurrent.futures

    skill_dir = _validate_path(request.skill_directory, label="skill_directory")

    if not skill_dir.exists():
        raise HTTPException(status_code=404, detail=f"Skill directory not found: {skill_dir}")

    if not skill_dir.is_dir():
        raise HTTPException(status_code=400, detail="skill_directory must be a directory")

    if not (skill_dir / "SKILL.md").exists():
        raise HTTPException(status_code=400, detail="SKILL.md not found in directory")

    custom_rules_path: str | None = None
    if request.custom_rules:
        validated_rules = _validate_path(request.custom_rules, label="custom_rules")
        if not validated_rules.is_dir():
            raise HTTPException(status_code=400, detail="custom_rules must be a directory")
        custom_rules_path = str(validated_rules)

    try:
        policy = _resolve_policy(request.policy)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    def run_scan():
        analyzers = _build_analyzers(
            policy,
            custom_rules=custom_rules_path,
            use_behavioral=request.use_behavioral,
            use_llm=request.use_llm,
            llm_provider=request.llm_provider,
            use_virustotal=request.use_virustotal,
            vt_api_key=vt_api_key,
            vt_upload_files=request.vt_upload_files,
            use_aidefense=request.use_aidefense,
            aidefense_api_key=aidefense_api_key,
            aidefense_api_url=request.aidefense_api_url,
            use_trigger=request.use_trigger,
            llm_consensus_runs=request.llm_consensus_runs,
        )
        scanner = SkillScanner(analyzers=analyzers, policy=policy)
        # 使用 strict_mode 参数控制验证模式，默认 lenient
        return scanner.scan_skill(skill_dir, lenient=not request.strict_mode)

    try:
        loop = asyncio.get_running_loop()
        with concurrent.futures.ThreadPoolExecutor() as executor:
            result = await loop.run_in_executor(executor, run_scan)

        # Meta-analysis
        meta_analysis_result = None

        # 记录 meta 分析条件检查
        logger.info(f"Meta-analysis check: enable_meta={request.enable_meta}, "
                   f"META_AVAILABLE={META_AVAILABLE}, "
                   f"findings_count={len(result.findings)}")

        if (
            request.enable_meta
            and META_AVAILABLE
            and MetaAnalyzer is not None
            and apply_meta_analysis_to_results is not None
            and len(result.findings) > 0
        ):
            try:
                from ..core.loader import SkillLoader

                # 显式传递 API key
                meta_api_key = os.getenv("SKILL_SCANNER_META_LLM_API_KEY") or os.getenv("SKILL_SCANNER_LLM_API_KEY")
                logger.info(f"Initializing MetaAnalyzer with API key: {'configured' if meta_api_key else 'MISSING'}")

                meta_analyzer = MetaAnalyzer(policy=policy, api_key=meta_api_key)
                # Meta 分析也使用 lenient 模式，与主扫描保持一致
                loader = SkillLoader()
                skill = loader.load_skill(skill_dir, lenient=not request.strict_mode)

                logger.info(f"Starting meta-analysis for {len(result.findings)} findings...")
                meta_result = await meta_analyzer.analyze_with_findings(
                    skill=skill,
                    findings=result.findings,
                    analyzers_used=result.analyzers_used,
                )

                filtered_findings = apply_meta_analysis_to_results(
                    original_findings=result.findings,
                    meta_result=meta_result,
                    skill=skill,
                )
                result.findings = filtered_findings
                result.analyzers_used.append("meta_analyzer")

                # 保存 meta 分析结果用于响应
                # 获取 llm_primary_threats 从 scan_metadata
                llm_primary_threats = (result.scan_metadata or {}).get("llm_primary_threats", [])
                meta_analysis_result = meta_result.to_dict(llm_primary_threats=llm_primary_threats)
                logger.info(f"Meta-analysis completed: {meta_analysis_result.get('summary', {})}")
            except Exception as meta_error:
                logger.warning("Meta-analysis failed: %s", meta_error)

        # Convert meta_analysis dict to Pydantic model for proper Swagger documentation
        meta_analysis_response: MetaAnalysisResponse | None = None
        if meta_analysis_result is not None:
            try:
                meta_analysis_response = MetaAnalysisResponse.model_validate(meta_analysis_result)
            except Exception as e:
                logger.warning("Failed to convert meta_analysis to response model: %s", e)

        scan_id = str(uuid.uuid4())
        return ScanResponse(
            scan_id=scan_id,
            skill_name=result.skill_name,
            is_safe=result.is_safe,
            max_severity=result.max_severity.value,
            findings_count=len(result.findings),
            scan_duration_seconds=result.scan_duration_seconds,
            timestamp=result.timestamp.isoformat(),
            findings=[f.to_dict() for f in result.findings],
            meta_analysis=meta_analysis_response,
        )

    except ValueError as e:
        category, reason = _categorize_error(e)
        detail = _build_error_detail(category, reason, debug_mode=os.getenv("DEBUG") == "true")
        raise HTTPException(status_code=_get_error_status_code(category), detail=detail)
    except Exception as e:
        category, reason = _categorize_error(e)
        logger.exception("Scan failed: %s - %s", category, reason)
        debug_mode = os.getenv("DEBUG") == "true"
        detail = _build_error_detail(category, reason, debug_mode=debug_mode)
        raise HTTPException(status_code=_get_error_status_code(category), detail=detail)


@router.post("/scan-upload")
async def scan_uploaded_skill(
    file: UploadFile = File(..., description="ZIP file containing skill package"),
    policy: str | None = Form(None, description="Scan policy: preset name or path to YAML"),
    custom_rules: str | None = Form(None, description="Path to custom YARA rules directory"),
    use_llm: bool = Form(False, description="Enable LLM analyzer"),
    llm_provider: str = Form("anthropic", description="LLM provider"),
    use_behavioral: bool = Form(False, description="Enable behavioral analyzer"),
    use_virustotal: bool = Form(False, description="Enable VirusTotal scanner"),
    vt_api_key: str | None = Header(None, alias="X-VirusTotal-Key"),
    vt_upload_files: bool = Form(False, description="Upload unknown files to VirusTotal"),
    use_aidefense: bool = Form(False, description="Enable AI Defense analyzer"),
    aidefense_api_key: str | None = Header(None, alias="X-AIDefense-Key"),
    aidefense_api_url: str | None = Form(None, description="AI Defense API URL"),
    use_trigger: bool = Form(False, description="Enable trigger specificity analysis"),
    enable_meta: bool = Form(False, description="Enable meta-analysis for FP filtering"),
    llm_consensus_runs: int = Form(1, description="Number of LLM consensus runs"),
    zip_password: str | None = Form(None, description="Password for encrypted ZIP files"),
):
    """Scan an uploaded skill package (ZIP file)."""
    if not file.filename or not file.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="File must be a ZIP archive")

    # 验证 ZIP 密码
    _validate_zip_password(zip_password)

    temp_dir = Path(tempfile.mkdtemp(prefix="skill_scanner_"))

    try:
        # Stream upload with size limit to avoid memory exhaustion
        zip_path = temp_dir / file.filename
        total_read = 0
        chunk_size = 1024 * 1024  # 1 MB chunks
        with open(zip_path, "wb") as f:
            while True:
                chunk = await file.read(chunk_size)
                if not chunk:
                    break
                total_read += len(chunk)
                if total_read > MAX_UPLOAD_SIZE_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail=f"Upload exceeds maximum size of {MAX_UPLOAD_SIZE_BYTES // (1024 * 1024)} MB",
                    )
                f.write(chunk)

        # 使用安全的ZIP解压helper函数
        extract_root = (temp_dir / "extracted").resolve()
        _extract_zip_with_security(zip_path, extract_root, zip_password)

        extracted_dir = temp_dir / "extracted"
        skill_dirs = list(extracted_dir.rglob("SKILL.md"))

        if not skill_dirs:
            raise HTTPException(status_code=400, detail="No SKILL.md found in uploaded archive")

        skill_dir = skill_dirs[0].parent

        request = ScanRequest(
            skill_directory=str(skill_dir),
            policy=policy,
            custom_rules=custom_rules,
            use_llm=use_llm,
            llm_provider=llm_provider,
            use_behavioral=use_behavioral,
            use_virustotal=use_virustotal,
            vt_upload_files=vt_upload_files,
            use_aidefense=use_aidefense,
            aidefense_api_url=aidefense_api_url,
            use_trigger=use_trigger,
            enable_meta=enable_meta,
            llm_consensus_runs=llm_consensus_runs,
        )

        return await scan_skill(request, vt_api_key=vt_api_key, aidefense_api_key=aidefense_api_key)

    except HTTPException:
        # HTTPException直接传递（状态码已在抛出时设置）
        raise
    except ValueError as e:
        category, reason = _categorize_error(e)
        detail = _build_error_detail(category, reason, debug_mode=os.getenv("DEBUG") == "true")
        raise HTTPException(status_code=_get_error_status_code(category), detail=detail)
    except Exception as e:
        category, reason = _categorize_error(e)
        logger.exception("Upload scan failed: %s - %s", category, reason)
        debug_mode = os.getenv("DEBUG") == "true"
        detail = _build_error_detail(category, reason, debug_mode=debug_mode)
        raise HTTPException(status_code=_get_error_status_code(category), detail=detail)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


@router.post("/scan-upload-async")
async def scan_uploaded_skill_async(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description="ZIP file containing skill package"),
    policy: str | None = Form(None, description="Scan policy: preset name or path to YAML"),
    custom_rules: str | None = Form(None, description="Path to custom YARA rules directory"),
    use_llm: bool = Form(False, description="Enable LLM analyzer"),
    llm_provider: str = Form("anthropic", description="LLM provider"),
    use_behavioral: bool = Form(False, description="Enable behavioral analyzer"),
    use_virustotal: bool = Form(False, description="Enable VirusTotal scanner"),
    vt_api_key: str | None = Header(None, alias="X-VirusTotal-Key"),
    vt_upload_files: bool = Form(False, description="Upload unknown files to VirusTotal"),
    use_aidefense: bool = Form(False, description="Enable AI Defense analyzer"),
    aidefense_api_key: str | None = Header(None, alias="X-AIDefense-Key"),
    aidefense_api_url: str | None = Form(None, description="AI Defense API URL"),
    use_trigger: bool = Form(False, description="Enable trigger specificity analysis"),
    enable_meta: bool = Form(False, description="Enable meta-analysis for FP filtering"),
    llm_consensus_runs: int = Form(1, description="Number of LLM consensus runs"),
    zip_password: str | None = Form(None, description="Password for encrypted ZIP files"),
    strict_mode: bool = Form(False, description="Enable strict validation (fail on missing SKILL.md fields)"),
):
    """异步扫描上传的技能包（ZIP 文件）。

    立即返回 scan_id，使用 GET /scan-upload-async/{scan_id} 查询结果。
    """
    if not file.filename or not file.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="File must be a ZIP archive")

    # 验证 ZIP 密码
    _validate_zip_password(zip_password)

    # 创建临时目录（不会在请求结束时清理）
    temp_dir = Path(tempfile.mkdtemp(prefix="skill_scanner_async_"))

    try:
        # 保存上传文件
        zip_path = temp_dir / file.filename
        total_read = 0
        chunk_size = 1024 * 1024  # 1 MB chunks

        with open(zip_path, "wb") as f:
            while True:
                chunk = await file.read(chunk_size)
                if not chunk:
                    break
                total_read += len(chunk)
                if total_read > MAX_UPLOAD_SIZE_BYTES:
                    shutil.rmtree(temp_dir, ignore_errors=True)
                    raise HTTPException(
                        status_code=413,
                        detail=f"Upload exceeds maximum size of {MAX_UPLOAD_SIZE_BYTES // (1024 * 1024)} MB",
                    )
                f.write(chunk)

        # 生成 scan_id
        scan_id = str(uuid.uuid4())

        # 设置缓存状态为 processing
        scan_results_cache.set(scan_id, {"status": "processing", "started_at": datetime.now().isoformat(), "result": None})

        # 启动后台任务（不在 finally 中清理临时目录）
        background_tasks.add_task(
            run_upload_scan,
            scan_id,
            zip_path,
            temp_dir,
            policy,
            custom_rules,
            use_llm,
            llm_provider,
            use_behavioral,
            use_virustotal,
            vt_upload_files,
            use_aidefense,
            aidefense_api_url,
            use_trigger,
            enable_meta,
            llm_consensus_runs,
            vt_api_key,
            aidefense_api_key,
            zip_password,
            strict_mode,
        )

        return {
            "scan_id": scan_id,
            "status": "processing",
            "message": "scan-upload started. Use GET /scan-upload-async/{scan_id} to check status.",
        }

    except HTTPException:
        # 重新抛出 HTTP 异常
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise

    except Exception as e:
        # 清理临时目录
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise HTTPException(status_code=500, detail=f"Failed to start async scan: {str(e)}") from e


@router.post("/scan-batch")
async def scan_batch(
    request: BatchScanRequest,
    background_tasks: BackgroundTasks,
    vt_api_key: str | None = Header(None, alias="X-VirusTotal-Key"),
    aidefense_api_key: str | None = Header(None, alias="X-AIDefense-Key"),
):
    """Scan multiple skills in a directory (batch scan)."""
    skills_dir = _validate_path(request.skills_directory, label="skills_directory")

    if not skills_dir.exists():
        raise HTTPException(status_code=404, detail=f"Skills directory not found: {skills_dir}")

    if not skills_dir.is_dir():
        raise HTTPException(status_code=400, detail="skills_directory must be a directory")

    scan_id = str(uuid.uuid4())
    scan_results_cache.set(scan_id, {"status": "processing", "started_at": datetime.now().isoformat(), "result": None})

    background_tasks.add_task(run_batch_scan, scan_id, request, vt_api_key, aidefense_api_key)

    return {
        "scan_id": scan_id,
        "status": "processing",
        "message": "Batch scan started. Use GET /scan-batch/{scan_id} to check status.",
    }


@router.get("/scan-batch/{scan_id}")
async def get_batch_scan_result(scan_id: str):
    """Get results of a batch scan."""
    cached = scan_results_cache.get_valid(scan_id)
    if cached is None:
        raise HTTPException(status_code=404, detail="Scan ID not found or expired")

    if cached["status"] == "processing":
        return {"scan_id": scan_id, "status": "processing", "started_at": cached["started_at"]}
    elif cached["status"] == "completed":
        return {
            "scan_id": scan_id,
            "status": "completed",
            "started_at": cached["started_at"],
            "completed_at": cached.get("completed_at"),
            "result": cached["result"],
        }
    else:
        return {"scan_id": scan_id, "status": "error", "error": cached.get("error", "Unknown error")}


@router.get("/scan-upload-async/{scan_id}")
async def get_upload_scan_result(scan_id: str):
    """获取异步扫描结果。

    返回扫描状态：
    - processing: 扫描进行中
    - completed: 扫描完成，包含完整结果
    - error: 扫描失败，包含错误信息
    """
    cached = scan_results_cache.get_valid(scan_id)
    if cached is None:
        raise HTTPException(status_code=404, detail="Scan ID not found or expired")

    if cached["status"] == "processing":
        return {"scan_id": scan_id, "status": "processing", "started_at": cached["started_at"]}
    elif cached["status"] == "completed":
        return {
            "scan_id": scan_id,
            "status": "completed",
            "started_at": cached["started_at"],
            "completed_at": cached.get("completed_at"),
            "result": cached["result"],
        }
    else:
        return {"scan_id": scan_id, "status": "error", "error": cached.get("error", "Unknown error")}


def run_batch_scan(
    scan_id: str,
    request: BatchScanRequest,
    vt_api_key: str | None = None,
    aidefense_api_key: str | None = None,
):
    """Background task to run batch scan."""
    try:
        policy = _resolve_policy(request.policy)

        custom_rules_path: str | None = None
        if request.custom_rules:
            custom_rules_path = str(_validate_path(request.custom_rules, label="custom_rules"))

        analyzers = _build_analyzers(
            policy,
            custom_rules=custom_rules_path,
            use_behavioral=request.use_behavioral,
            use_llm=request.use_llm,
            llm_provider=request.llm_provider,
            use_virustotal=request.use_virustotal,
            vt_api_key=vt_api_key,
            vt_upload_files=request.vt_upload_files,
            use_aidefense=request.use_aidefense,
            aidefense_api_key=aidefense_api_key,
            aidefense_api_url=request.aidefense_api_url,
            use_trigger=request.use_trigger,
            llm_consensus_runs=request.llm_consensus_runs,
        )

        scanner = SkillScanner(analyzers=analyzers, policy=policy)
        report = scanner.scan_directory(
            _validate_path(request.skills_directory, label="skills_directory"),
            recursive=request.recursive,
            check_overlap=request.check_overlap,
        )

        # Meta-analysis per skill
        if (
            request.enable_meta
            and META_AVAILABLE
            and MetaAnalyzer is not None
            and apply_meta_analysis_to_results is not None
        ):
            import asyncio

            async def _run_batch_meta(scanner_ref, report_ref, policy_ref, strict_mode_ref):
                # 显式传递 API key
                meta_api_key = os.getenv("SKILL_SCANNER_META_LLM_API_KEY") or os.getenv("SKILL_SCANNER_LLM_API_KEY")
                logger.info(f"Batch meta-analysis: API key {'configured' if meta_api_key else 'MISSING'}")

                meta_analyzer = MetaAnalyzer(policy=policy_ref, api_key=meta_api_key)

                meta_results_count = 0
                for result in report_ref.scan_results:
                    if result.findings:
                        try:
                            skill_dir_path = Path(result.skill_directory)
                            # Meta 分析使用与主扫描相同的验证模式
                            skill = scanner_ref.loader.load_skill(skill_dir_path, lenient=not strict_mode_ref)
                            logger.info(f"Running meta-analysis for skill: {result.skill_name} ({len(result.findings)} findings)")

                            meta_result = await meta_analyzer.analyze_with_findings(
                                skill=skill,
                                findings=result.findings,
                                analyzers_used=result.analyzers_used,
                            )
                            filtered_findings = apply_meta_analysis_to_results(
                                original_findings=result.findings,
                                meta_result=meta_result,
                                skill=skill,
                            )
                            result.findings = filtered_findings
                            result.analyzers_used.append("meta_analyzer")
                            meta_results_count += 1

                            # 获取 llm_primary_threats 从 scan_metadata
                            llm_primary_threats = (result.scan_metadata or {}).get("llm_primary_threats", [])
                            meta_analysis_dict = meta_result.to_dict(llm_primary_threats=llm_primary_threats)

                            # 将完整的 meta_analysis 添加到 scan_metadata
                            if result.scan_metadata is None:
                                result.scan_metadata = {}
                            result.scan_metadata["meta_analysis"] = meta_analysis_dict

                            summary = meta_analysis_dict.get("summary", {})
                            logger.info(f"Meta-analysis completed for {result.skill_name}: {summary}")
                        except Exception as e:
                            logger.warning(f"Meta-analysis failed for {result.skill_name}: {e}")

                logger.info(f"Batch meta-analysis completed: {meta_results_count}/{len(report_ref.scan_results)} skills processed")

            try:
                asyncio.run(_run_batch_meta(scanner, report, policy, request.strict_mode))
            except Exception as e:
                logger.warning(f"Batch meta-analysis failed: {e}")

        # Keep batch summary counters consistent with potentially mutated
        # per-skill findings (e.g., after meta-analysis filtering).
        _recompute_report_summary(report)

        started_at = (scan_results_cache.get_valid(scan_id) or {}).get("started_at", datetime.now().isoformat())
        scan_results_cache.set(
            scan_id,
            {
                "status": "completed",
                "started_at": started_at,
                "completed_at": datetime.now().isoformat(),
                "result": report.to_dict(),
            },
        )

    except Exception as e:
        category, reason = _categorize_error(e)
        logger.exception("Batch scan failed: %s - %s", category, reason)
        started_at = (scan_results_cache.get_valid(scan_id) or {}).get("started_at", datetime.now().isoformat())

        # 构建结构化错误响应
        error_response = {
            "status": "error",
            "started_at": started_at,
            "error_category": category,
            "error_reason": reason,
            "error": str(e),  # 保留原始错误信息以兼容旧客户端
        }

        # 调试模式添加堆栈信息
        if os.getenv("DEBUG") == "true":
            import traceback

            error_response["stack_trace"] = traceback.format_exc()

        scan_results_cache.set(scan_id, error_response)


def run_upload_scan(
    scan_id: str,
    zip_path: Path,
    temp_dir: Path,
    policy_str: str | None,
    custom_rules: str | None,
    use_llm: bool,
    llm_provider: str,
    use_behavioral: bool,
    use_virustotal: bool,
    vt_upload_files: bool,
    use_aidefense: bool,
    aidefense_api_url: str | None,
    use_trigger: bool,
    enable_meta: bool,
    llm_consensus_runs: int,
    vt_api_key: str | None = None,
    aidefense_api_key: str | None = None,
    zip_password: str | None = None,
    strict_mode: bool = False,
):
    """Background task to scan uploaded ZIP file."""
    try:
        import stat
        import zipfile

        # 解压 ZIP 文件（使用安全的helper函数）
        extract_root = (temp_dir / "extracted").resolve()
        _extract_zip_with_security(zip_path, extract_root, zip_password)

        # 查找 SKILL.md
        extracted_dir = temp_dir / "extracted"
        skill_dirs = list(extracted_dir.rglob("SKILL.md"))

        if not skill_dirs:
            raise ValueError("No SKILL.md found in uploaded archive")

        skill_dir = skill_dirs[0].parent

        # 解析策略
        policy = _resolve_policy(policy_str)

        custom_rules_path: str | None = None
        if custom_rules:
            custom_rules_path = str(_validate_path(custom_rules, label="custom_rules"))

        # 构建分析器
        analyzers = _build_analyzers(
            policy,
            custom_rules=custom_rules_path,
            use_behavioral=use_behavioral,
            use_llm=use_llm,
            llm_provider=llm_provider,
            use_virustotal=use_virustotal,
            vt_api_key=vt_api_key,
            vt_upload_files=vt_upload_files,
            use_aidefense=use_aidefense,
            aidefense_api_key=aidefense_api_key,
            aidefense_api_url=aidefense_api_url,
            use_trigger=use_trigger,
            llm_consensus_runs=llm_consensus_runs,
        )

        # 执行扫描
        scanner = SkillScanner(analyzers=analyzers, policy=policy)
        # API 默认使用 lenient 模式，以容忍缺少字段的 SKILL.md
        result = scanner.scan_skill(skill_dir, lenient=not strict_mode)

        # Meta 分析
        meta_analysis_result = None

        if (
            enable_meta
            and META_AVAILABLE
            and MetaAnalyzer is not None
            and apply_meta_analysis_to_results is not None
            and len(result.findings) > 0
        ):
            try:
                from ..core.loader import SkillLoader

                meta_api_key = os.getenv("SKILL_SCANNER_META_LLM_API_KEY") or os.getenv("SKILL_SCANNER_LLM_API_KEY")
                logger.info(f"Async meta-analysis: API key {'configured' if meta_api_key else 'MISSING'}")

                meta_analyzer = MetaAnalyzer(policy=policy, api_key=meta_api_key)
                # Meta 分析使用与主扫描相同的验证模式
                loader = SkillLoader()
                skill = loader.load_skill(skill_dir, lenient=not strict_mode)

                logger.info(f"Starting async meta-analysis for {len(result.findings)} findings...")

                async def _run_meta():
                    nonlocal meta_analysis_result
                    meta_result = await meta_analyzer.analyze_with_findings(
                        skill=skill,
                        findings=result.findings,
                        analyzers_used=result.analyzers_used,
                    )
                    return meta_result

                import asyncio

                meta_result = asyncio.run(_run_meta())
                filtered_findings = apply_meta_analysis_to_results(
                    original_findings=result.findings,
                    meta_result=meta_result,
                    skill=skill,
                )
                result.findings = filtered_findings
                result.analyzers_used.append("meta_analyzer")
                # 获取 llm_primary_threats 从 scan_metadata
                llm_primary_threats = (result.scan_metadata or {}).get("llm_primary_threats", [])
                meta_analysis_result = meta_result.to_dict(llm_primary_threats=llm_primary_threats)
                logger.info(f"Async meta-analysis completed: {meta_analysis_result.get('summary', {})}")

            except Exception as meta_error:
                logger.warning("Async meta-analysis failed: %s", meta_error)

        # 更新缓存为 completed
        started_at = (scan_results_cache.get_valid(scan_id) or {}).get("started_at", datetime.now().isoformat())
        scan_results_cache.set(
            scan_id,
            {
                "status": "completed",
                "started_at": started_at,
                "completed_at": datetime.now().isoformat(),
                "result": {
                    "scan_id": scan_id,
                    "skill_name": result.skill_name,
                    "is_safe": result.is_safe,
                    "max_severity": result.max_severity.value,
                    "findings_count": len(result.findings),
                    "scan_duration_seconds": result.scan_duration_seconds,
                    "timestamp": result.timestamp.isoformat(),
                    "findings": [f.to_dict() for f in result.findings],
                    "meta_analysis": meta_analysis_result,
                },
            },
        )

    except Exception as e:
        category, reason = _categorize_error(e)
        logger.exception("Async upload scan failed: %s - %s", category, reason)
        started_at = (scan_results_cache.get_valid(scan_id) or {}).get("started_at", datetime.now().isoformat())

        # 构建结构化错误响应
        error_response = {
            "status": "error",
            "started_at": started_at,
            "error_category": category,
            "error_reason": reason,
            "error": str(e),  # 保留原始错误信息以兼容旧客户端
        }

        # 调试模式添加堆栈信息
        if os.getenv("DEBUG") == "true":
            import traceback

            error_response["stack_trace"] = traceback.format_exc()

        scan_results_cache.set(scan_id, error_response)

    finally:
        # 清理临时目录
        shutil.rmtree(temp_dir, ignore_errors=True)


@router.get("/analyzers")
async def list_analyzers():
    """List available analyzers."""
    analyzers = [
        {
            "name": "static_analyzer",
            "description": "Pattern-based detection using YAML and YARA rules",
            "available": True,
            "rules_count": "90+",
        },
        {
            "name": "bytecode_analyzer",
            "description": "Python bytecode integrity verification against source",
            "available": True,
        },
        {
            "name": "pipeline_analyzer",
            "description": "Command pipeline taint analysis for data exfiltration",
            "available": True,
        },
    ]

    if BEHAVIORAL_AVAILABLE:
        analyzers.append(
            {
                "name": "behavioral_analyzer",
                "description": "Static dataflow analysis for Python files",
                "available": True,
            }
        )

    if LLM_AVAILABLE:
        analyzers.append(
            {
                "name": "llm_analyzer",
                "description": "Semantic analysis using LLM as a judge",
                "available": True,
                "providers": ["anthropic", "openai", "azure", "bedrock", "gemini"],
            }
        )

    if VIRUSTOTAL_AVAILABLE:
        analyzers.append(
            {
                "name": "virustotal_analyzer",
                "description": "Hash-based malware detection for binary files via VirusTotal",
                "available": True,
                "requires_api_key": True,
            }
        )

    if AIDEFENSE_AVAILABLE:
        analyzers.append(
            {
                "name": "aidefense_analyzer",
                "description": "Cisco AI Defense cloud-based threat detection",
                "available": True,
                "requires_api_key": True,
            }
        )

    if TRIGGER_AVAILABLE:
        analyzers.append(
            {
                "name": "trigger_analyzer",
                "description": "Trigger specificity analysis for overly generic descriptions",
                "available": True,
            }
        )

    if META_AVAILABLE:
        analyzers.append(
            {
                "name": "meta_analyzer",
                "description": "Second-pass LLM analysis for false positive filtering",
                "available": True,
                "requires": "2+ analyzers, LLM API key",
            }
        )

    return {"analyzers": analyzers}
