# utils/security.py

import os
import time
import ipaddress
from pathlib import Path
from urllib.parse import urlparse
from functools import wraps
from typing import Optional


class SecurityError(Exception):
    """Base exception for security-related errors"""
    pass


class PathTraversalError(SecurityError):
    """Raised when path traversal is detected"""
    pass


class SSRFError(SecurityError):
    """Raised when SSRF attempt is detected"""
    pass


# ============================================================================
# Path Validation
# ============================================================================

def validate_safe_path(filepath: str, base_dir: str = "url_examine") -> Path:
    """
    Validates that a file path is safe and within the expected directory.

    Args:
        filepath: The file path to validate
        base_dir: The base directory to restrict access to

    Returns:
        Path: Absolute resolved path if safe

    Raises:
        PathTraversalError: If path traversal is detected
    """
    try:
        # Create base directory if it doesn't exist
        base_path = Path(base_dir).resolve()
        base_path.mkdir(parents=True, exist_ok=True)

        # Get absolute path
        abs_path = Path(filepath).resolve()

        # Check if path is within base directory
        try:
            abs_path.relative_to(base_path)
        except ValueError:
            raise PathTraversalError(
                f"Path '{filepath}' is outside allowed directory '{base_dir}'"
            )

        return abs_path
    except Exception as e:
        if isinstance(e, PathTraversalError):
            raise
        raise PathTraversalError(f"Invalid path: {e}")


def sanitize_filename(filename: str) -> str:
    """
    Sanitizes a filename to prevent path traversal and dangerous characters.

    Args:
        filename: The filename to sanitize

    Returns:
        str: Sanitized filename
    """
    # Get just the basename (removes any path components)
    filename = os.path.basename(filename)

    # Remove dangerous characters
    dangerous_chars = ['..', '/', '\\', '\0', '\n', '\r']
    for char in dangerous_chars:
        filename = filename.replace(char, '')

    # Ensure filename isn't empty after sanitization
    if not filename or filename == '.':
        filename = 'output.json'

    return filename


# ============================================================================
# URL Validation (SSRF Protection)
# ============================================================================

ALLOWED_SCHEMES = ['http', 'https']
BLOCKED_HOSTS = [
    'localhost',
    '127.0.0.1',
    '0.0.0.0',
    '::1',
    '169.254.169.254',  # AWS metadata service
    'metadata.google.internal',  # GCP metadata
]


def validate_url(url: str, allow_private_ips: bool = False) -> bool:
    """
    Validates a URL to prevent SSRF attacks.

    Args:
        url: The URL to validate
        allow_private_ips: Whether to allow private IP addresses (default: False)

    Returns:
        bool: True if URL is safe

    Raises:
        SSRFError: If URL is potentially malicious
    """
    try:
        parsed = urlparse(url)

        # Check scheme
        if parsed.scheme not in ALLOWED_SCHEMES:
            raise SSRFError(
                f"URL scheme '{parsed.scheme}' not allowed. "
                f"Only {ALLOWED_SCHEMES} are permitted."
            )

        # Check for blocked hostnames
        hostname = parsed.hostname
        if not hostname:
            raise SSRFError("URL must have a valid hostname")

        hostname_lower = hostname.lower()
        if hostname_lower in BLOCKED_HOSTS:
            raise SSRFError(f"Access to '{hostname}' is blocked")

        # Check for private IP addresses
        if not allow_private_ips:
            try:
                ip = ipaddress.ip_address(hostname)
                if ip.is_private or ip.is_loopback or ip.is_link_local:
                    raise SSRFError(
                        f"Access to private IP address '{hostname}' is blocked. "
                        f"Use --allow-private-ips flag if this is intentional."
                    )
            except ValueError:
                # hostname is a domain name, not an IP - this is fine
                pass

        return True

    except SSRFError:
        raise
    except Exception as e:
        raise SSRFError(f"Invalid URL: {e}")


# ============================================================================
# Rate Limiting
# ============================================================================

def rate_limit(calls: int = 10, period: int = 60):
    """
    Decorator to rate limit function calls.

    Args:
        calls: Maximum number of calls allowed
        period: Time period in seconds

    Usage:
        @rate_limit(calls=10, period=60)
        def my_function():
            pass
    """
    def decorator(func):
        timestamps = []

        @wraps(func)
        def wrapper(*args, **kwargs):
            now = time.time()

            # Remove timestamps older than period
            timestamps[:] = [t for t in timestamps if now - t < period]

            # Check if rate limit exceeded
            if len(timestamps) >= calls:
                sleep_time = period - (now - timestamps[0]) + 0.1
                if sleep_time > 0:
                    time.sleep(sleep_time)
                    # Clean up old timestamps again
                    timestamps[:] = [t for t in timestamps if time.time() - t < period]

            timestamps.append(time.time())
            return func(*args, **kwargs)

        return wrapper
    return decorator


# ============================================================================
# Error Sanitization
# ============================================================================

def sanitize_error_message(error: Exception, expose_details: bool = False) -> str:
    """
    Sanitizes error messages to prevent information disclosure.

    Args:
        error: The exception to sanitize
        expose_details: Whether to expose detailed error info (for debugging)

    Returns:
        str: Sanitized error message
    """
    if expose_details:
        return str(error)

    # Generic error messages by exception type
    error_type = type(error).__name__

    generic_messages = {
        'FileNotFoundError': 'File not found',
        'PermissionError': 'Permission denied',
        'TimeoutError': 'Operation timed out',
        'ConnectionError': 'Connection failed',
        'SSLError': 'SSL/TLS error',
        'ValueError': 'Invalid input',
    }

    return generic_messages.get(error_type, 'An error occurred during analysis')


# ============================================================================
# API Key Validation
# ============================================================================

def validate_openai_api_key(api_key: str) -> bool:
    """
    Validates OpenAI API key format.

    Args:
        api_key: The API key to validate

    Returns:
        bool: True if format is valid

    Raises:
        ValueError: If API key format is invalid
    """
    if not api_key:
        raise ValueError("API key is empty")

    if not api_key.startswith('sk-'):
        raise ValueError(
            "Invalid OpenAI API key format. "
            "API keys should start with 'sk-'"
        )

    if len(api_key) < 20:
        raise ValueError("API key is too short")

    return True


# ============================================================================
# Resource Limits
# ============================================================================

def clamp_value(value: float, min_val: float, max_val: float) -> float:
    """
    Clamps a value between min and max.

    Args:
        value: The value to clamp
        min_val: Minimum allowed value
        max_val: Maximum allowed value

    Returns:
        float: Clamped value
    """
    return max(min_val, min(value, max_val))
