"""错误分类系统测试.

测试 API 路由中的错误分类、状态码映射和详情构建功能。
"""

import pytest

from skill_scanner.api.router import (
    _build_error_detail,
    _categorize_error,
    _get_error_status_code,
    _redact_password,
    _sanitize_stack_trace,
)
from skill_scanner.core.exceptions import SkillLoadError


class TestRedactPassword:
    """测试密码脱敏功能."""

    def test_redact_password_simple(self):
        """测试简单密码替换."""
        message = "Bad password 'secret123' for ZIP file"
        result = _redact_password(message, "secret123")
        assert result == "Bad password '***REDACTED***' for ZIP file"

    def test_redact_password_case_insensitive(self):
        """测试大小写不敏感替换."""
        message = "Bad password 'Secret123' for ZIP file"
        result = _redact_password(message, "secret123")
        assert "***REDACTED***" in result
        assert "Secret123" not in result

    def test_redact_password_none(self):
        """测试密码为 None 时直接返回消息."""
        message = "Some error message"
        result = _redact_password(message, None)
        assert result == message

    def test_redact_password_not_in_message(self):
        """测试密码不在消息中时直接返回消息."""
        message = "Some other error"
        result = _redact_password(message, "secret")
        assert result == message

    def test_redact_password_regex_escape(self):
        """测试特殊字符密码的转义."""
        message = "Error with password 'a.b.c'"
        result = _redact_password(message, "a.b.c")
        assert "***REDACTED***" in result
        assert "a.b.c" not in result


class TestSanitizeStackTrace:
    """测试堆栈跟踪清理功能."""

    def test_sanitize_removes_absolute_paths_unix(self):
        """测试移除 Unix 绝对路径."""
        stack = 'File "/home/user/project/skills/file.py", line 10'
        result = _sanitize_stack_trace(stack)
        # 清理后保留最后两段路径
        assert "skills/file.py" in result
        assert "/home/user" not in result
        assert "/home/user/project" not in result

    def test_sanitize_removes_absolute_paths_windows(self):
        """测试移除 Windows 绝对路径."""
        stack = 'File "C:\\Users\\user\\project\\file.py", line 10'
        result = _sanitize_stack_trace(stack)
        # 清理后保留最后两段路径（Windows 使用反斜杠）
        assert "project\\file.py" in result
        assert "C:\\Users\\user" not in result
        assert "C:\\\\" not in result

    def test_sanitize_removes_home_path(self):
        """测试移除用户主目录路径."""
        import os
        stack = f'File "{os.path.expanduser("~")}/project/file.py", line 10'
        result = _sanitize_stack_trace(stack)
        assert "~/project/file.py" in result or "project/file.py" in result

    def test_sanitize_preserves_line_numbers(self):
        """测试保留行号信息."""
        stack = 'File "/path/to/file.py", line 42, in test_function'
        result = _sanitize_stack_trace(stack)
        assert "line 42" in result
        assert "test_function" in result


class TestCategorizeError:
    """测试错误分类功能."""

    def test_skill_md_format_error_missing_name(self):
        """测试 SKILL.md 缺少 name 字段的分类."""
        error = SkillLoadError("missing required field: name")
        category, reason = _categorize_error(error)
        assert category == "SKILL_MD_FORMAT_ERROR"
        assert "name" in reason.lower()

    def test_skill_md_format_error_missing_description(self):
        """测试 SKILL.md 缺少 description 字段的分类."""
        error = SkillLoadError("missing required field: description")
        category, reason = _categorize_error(error)
        assert category == "SKILL_MD_FORMAT_ERROR"
        assert "description" in reason.lower()

    def test_skill_md_not_found(self):
        """测试 SKILL.md 文件不存在的分类."""
        error = SkillLoadError("SKILL.md not found")
        category, reason = _categorize_error(error)
        assert category == "SKILL_MD_NOT_FOUND"

    def test_file_encoding_error(self):
        """测试文件编码错误的分类."""
        error = ValueError("null byte in file")
        category, reason = _categorize_error(error)
        assert category == "FILE_ENCODING_ERROR"

    def test_llm_auth_error(self):
        """测试 LLM 认证错误的分类."""
        error = Exception("LLM API key authentication failed")
        category, reason = _categorize_error(error)
        assert category == "LLM_AUTH_ERROR"

    def test_llm_timeout_error(self):
        """测试 LLM 超时错误的分类."""
        error = Exception("LLM request timeout after 30s")
        category, reason = _categorize_error(error)
        assert category == "LLM_TIMEOUT_ERROR"

    def test_llm_rate_limit_error(self):
        """测试 LLM 速率限制错误的分类."""
        error = Exception("LLM rate limit exceeded: 429")
        category, reason = _categorize_error(error)
        assert category == "LLM_RATE_LIMIT_ERROR"

    def test_policy_config_error(self):
        """测试策略配置错误的分类."""
        error = ValueError("Unknown policy: custom_policy")
        category, reason = _categorize_error(error)
        assert category == "POLICY_CONFIG_ERROR"

    def test_file_not_found_error(self):
        """测试文件不存在错误的分类."""
        error = FileNotFoundError("Skill directory not found")
        category, reason = _categorize_error(error)
        assert category == "FILE_NOT_FOUND"

    def test_permission_error(self):
        """测试权限错误的分类."""
        error = PermissionError("Permission denied")
        category, reason = _categorize_error(error)
        assert category == "PERMISSION_ERROR"

    def test_unknown_error(self):
        """测试未知错误的分类."""
        error = RuntimeError("Some unknown error")
        category, reason = _categorize_error(error)
        assert category == "UNKNOWN_ERROR"


class TestGetErrorStatusCode:
    """测试错误状态码映射功能."""

    def test_skill_md_format_error_status(self):
        """测试 SKILL_MD_FORMAT_ERROR 的状态码."""
        status = _get_error_status_code("SKILL_MD_FORMAT_ERROR")
        assert status == 400

    def test_file_size_error_status(self):
        """测试 FILE_SIZE_ERROR 的状态码."""
        status = _get_error_status_code("FILE_SIZE_ERROR")
        assert status == 413

    def test_zip_decryption_failed_status(self):
        """测试 ZIP_DECRYPTION_FAILED 的状态码."""
        status = _get_error_status_code("ZIP_DECRYPTION_FAILED")
        assert status == 401

    def test_llm_rate_limit_status(self):
        """测试 LLM_RATE_LIMIT_ERROR 的状态码."""
        status = _get_error_status_code("LLM_RATE_LIMIT_ERROR")
        assert status == 429

    def test_unknown_error_status(self):
        """测试未知错误的默认状态码."""
        status = _get_error_status_code("UNKNOWN_ERROR")
        assert status == 500


class TestBuildErrorDetail:
    """测试错误详情构建功能."""

    def test_normal_mode_no_stack(self):
        """测试非调试模式不包含堆栈跟踪."""
        detail = _build_error_detail("TEST_ERROR", "Test reason", debug_mode=False)
        assert "TEST_ERROR: Test reason" == detail
        assert "Stack trace:" not in detail

    def test_debug_mode_includes_stack(self):
        """测试调试模式包含堆栈跟踪."""
        detail = _build_error_detail("TEST_ERROR", "Test reason", debug_mode=True)
        assert "TEST_ERROR: Test reason" in detail
        assert "Stack trace:" in detail

    def test_debug_mode_stack_is_sanitized(self):
        """测试调试模式堆栈跟踪已清理."""
        detail = _build_error_detail("TEST_ERROR", "Test reason", debug_mode=True)
        # 堆栈跟踪不应包含绝对路径
        assert "C:\\" not in detail
        assert "/home/" not in detail
