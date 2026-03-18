import html
import mimetypes
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse

import validators

try:
    import magic as _magic  # type: ignore[import-untyped]

    _HAS_MAGIC = True
except (ImportError, OSError):
    _magic = None  # type: ignore[assignment]
    _HAS_MAGIC = False


class InputValidator:
    # Allowed file extensions and their corresponding MIME types
    ALLOWED_FILE_TYPES = {
        "pdf": "application/pdf",
        "txt": "text/plain",
        "json": "application/json",
        "yaml": "application/x-yaml",
        "jpg": "image/jpeg",
        "jpeg": "image/jpeg",
        "png": "image/png",
        "csv": "text/csv",
    }

    # Maximum file size (10MB)
    MAX_FILE_SIZE = 10 * 1024 * 1024

    @staticmethod
    def validate_email(email: str) -> bool:
        """
        Validate email address format using comprehensive checks.

        Args:
            email (str): Email address to validate

        Returns:
            bool: True if email is valid, False otherwise
        """
        if not isinstance(email, str):
            return False

        # Basic format check
        if not validators.email(email):
            return False

        # Additional checks
        if len(email) > 254:  # Maximum length per RFC 5321
            return False

        # Check for common patterns that might indicate invalid emails
        invalid_patterns = [
            r"\s",  # No whitespace
            r"\.{2,}",  # No consecutive dots
            r"^[.-]",  # Don't start with dot or hyphen
            r"[.-]@",  # Don't end local part with dot or hyphen
            r"[^\x20-\x7E]",  # ASCII printable characters only
        ]

        return not any(re.search(pattern, email) for pattern in invalid_patterns)

    @staticmethod
    def validate_password(password: str, min_length: int = 12) -> Dict[str, Any]:
        """
        Validate password strength with detailed feedback.

        Args:
            password (str): Password to validate
            min_length (int): Minimum password length

        Returns:
            Dict containing validation result and detailed feedback
        """
        result = {"valid": False, "errors": []}

        if not isinstance(password, str):
            result["errors"].append("Password must be a string")
            return result

        # Length check
        if len(password) < min_length:
            result["errors"].append(f"Password must be at least {min_length} characters long")

        # Complexity requirements
        checks = [
            (r"[A-Z]", "at least one uppercase letter"),
            (r"[a-z]", "at least one lowercase letter"),
            (r"\d", "at least one number"),
            (r'[!@#$%^&*(),.?":{}|<>]', "at least one special character"),
        ]

        for pattern, message in checks:
            if not re.search(pattern, password):
                result["errors"].append(f"Password must contain {message}")

        # Check for common patterns to avoid
        common_patterns = [
            (r"(.)\1{2,}", "repeated characters"),
            (r"12345|qwerty|password", "common sequences"),
            (r"admin|root|user", "common words"),
        ]

        for pattern, message in common_patterns:
            if re.search(pattern, password.lower()):
                result["errors"].append(f"Password contains {message}")

        result["valid"] = len(result["errors"]) == 0
        return result

    @staticmethod
    def sanitize_input(input_data: Union[str, Dict, List], max_length: int = 1000) -> Union[str, Dict, List]:
        """
        Sanitize input with comprehensive protection against XSS and injection.

        Args:
            input_data: Input to sanitize
            max_length: Maximum allowed length for strings

        Returns:
            Sanitized input
        """

        def sanitize_string(s: str) -> str:
            if not isinstance(s, str):
                return ""

            # Convert to string and truncate
            s = str(s)[:max_length]

            # HTML escape
            s = html.escape(s)

            # Remove potentially dangerous patterns
            dangerous_patterns = [
                r"javascript:",
                r"data:",
                r"vbscript:",
                r"onload=",
                r"onerror=",
                r"<script",
                r"</script>",
                r"eval\(",
                r"expression\(",
                r"<!--",
                r"-->",
            ]

            for pattern in dangerous_patterns:
                s = re.sub(pattern, "", s, flags=re.IGNORECASE)

            return s

        if isinstance(input_data, str):
            return sanitize_string(input_data)

        if isinstance(input_data, dict):
            return {
                sanitize_string(str(k)): InputValidator.sanitize_input(v, max_length) for k, v in input_data.items()
            }

        if isinstance(input_data, list):
            return [InputValidator.sanitize_input(item, max_length) for item in input_data]

        return input_data

    @staticmethod
    def validate_file_path(file_path: str, allowed_base_paths: List[str]) -> bool:
        """
        Validate file path for traversal attacks and permissions.

        Args:
            file_path: Path to validate
            allowed_base_paths: List of allowed base paths

        Returns:
            bool: True if path is valid and secure
        """
        if not isinstance(file_path, str):
            return False

        try:
            # Resolve to absolute path
            abs_path = os.path.abspath(file_path)
            path_obj = Path(abs_path)

            # Check if path exists within allowed base paths
            return any(str(path_obj).startswith(str(Path(base).resolve())) for base in allowed_base_paths)
        except Exception:
            return False

    @staticmethod
    def validate_file_content(file_path: str, max_size: Optional[int] = None) -> Dict[str, Any]:
        """
        Validate file content type and size.

        Args:
            file_path: Path to the file
            max_size: Maximum allowed file size in bytes

        Returns:
            Dict containing validation results
        """
        result = {"valid": False, "errors": []}

        if not os.path.exists(file_path):
            result["errors"].append("File does not exist")
            return result

        # Size check
        file_size = os.path.getsize(file_path)
        max_size = max_size or InputValidator.MAX_FILE_SIZE

        if file_size > max_size:
            result["errors"].append(f"File size exceeds maximum allowed size of {max_size} bytes")
            return result

        try:
            extension = os.path.splitext(file_path)[1].lower().lstrip(".")
            if extension not in InputValidator.ALLOWED_FILE_TYPES:
                result["errors"].append("File type not allowed")
                return result

            if _HAS_MAGIC and _magic is not None:
                # Deep MIME-type check via libmagic when available
                mime = _magic.Magic(mime=True)
                file_type = mime.from_file(file_path)
                expected_mime = InputValidator.ALLOWED_FILE_TYPES[extension]
                if file_type != expected_mime:
                    result["errors"].append("File content does not match extension")
                    return result
            else:
                # Fallback: trust the extension (libmagic not installed)
                pass

            result["valid"] = True
            return result

        except Exception as e:
            result["errors"].append(f"File validation error: {str(e)}")
            return result

    @staticmethod
    def validate_url(url: str) -> bool:
        """
        Validate URL format and security.

        Args:
            url: URL to validate

        Returns:
            bool: True if URL is valid and secure
        """
        if not isinstance(url, str):
            return False

        try:
            # Basic URL validation
            if not validators.url(url):
                return False

            # Parse URL
            parsed = urlparse(url)

            # Require HTTPS
            if parsed.scheme != "https":
                return False

            # Check for common security issues
            security_checks = [
                r"javascript:",
                r"data:",
                r"vbscript:",
                r"file:",
                r"[<>]",
                r"%00",  # Null byte
                r"%0d",  # Carriage return
                r"%0a",  # Line feed
            ]

            return not any(re.search(pattern, url, re.IGNORECASE) for pattern in security_checks)

        except Exception:
            return False

    @staticmethod
    def validate_scan_parameters(params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate parameters for a security scan with detailed feedback.

        Args:
            params: Scan parameters to validate

        Returns:
            Dict containing validation results and errors
        """
        result = {"valid": False, "errors": []}

        required_params = {
            "target": (str, ["url", "hostname", "ip"]),
            "scan_type": (str, ["full", "quick", "custom"]),
        }

        optional_params = {
            "depth": (int, (1, 10)),
            "timeout": (int, (30, 3600)),
            "exclude_paths": (list, None),
            "custom_rules": (dict, None),
        }

        # Validate required parameters
        for param, (expected_type, allowed_values) in required_params.items():
            if param not in params:
                result["errors"].append(f"Missing required parameter: {param}")
                continue

            if not isinstance(params[param], expected_type):
                result["errors"].append(f"Invalid type for {param}")
                continue

            if allowed_values and params[param] not in allowed_values:
                result["errors"].append(f"Invalid value for {param}")

        # Validate optional parameters
        for param, (expected_type, value_range) in optional_params.items():
            if param in params:
                if not isinstance(params[param], expected_type):
                    result["errors"].append(f"Invalid type for {param}")
                    continue

                if value_range and isinstance(params[param], (int, float)):
                    min_val, max_val = value_range
                    if not min_val <= params[param] <= max_val:
                        result["errors"].append(f"{param} must be between {min_val} and {max_val}")

        result["valid"] = len(result["errors"]) == 0
        return result
