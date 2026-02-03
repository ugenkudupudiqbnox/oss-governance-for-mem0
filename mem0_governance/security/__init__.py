"""
Security Module

Provides security utilities including secret management and input validation.
No hard-coded secrets allowed.
"""

from typing import Optional, Dict, Any, List
import os
import re
import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta


class SecretManager:
    """
    Manages secrets without hard-coding them in source code.
    
    Secrets should be provided via environment variables or secure vaults.
    """
    
    def __init__(self, prefix: str = "MEM0_GOV_") -> None:
        """
        Initialize secret manager.
        
        Args:
            prefix: Environment variable prefix for secrets
        """
        self._prefix = prefix
        self._cache: Dict[str, str] = {}
        
    def get_secret(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """
        Retrieve a secret from environment variables.
        
        Args:
            key: Secret key name
            default: Default value if not found
            
        Returns:
            Secret value or default
        """
        # Check cache first
        if key in self._cache:
            return self._cache[key]
        
        # Look up in environment with prefix
        env_key = f"{self._prefix}{key.upper()}"
        value = os.environ.get(env_key, default)
        
        # Cache if found
        if value is not None:
            self._cache[key] = value
        
        return value
    
    def set_secret(self, key: str, value: str) -> None:
        """
        Set a secret in the cache (for testing purposes).
        
        In production, secrets should be set via environment variables.
        """
        self._cache[key] = value
    
    def has_secret(self, key: str) -> bool:
        """Check if a secret exists"""
        return self.get_secret(key) is not None
    
    def validate_secret_strength(self, secret: str, min_length: int = 32) -> bool:
        """
        Validate that a secret meets minimum security requirements.
        
        Args:
            secret: Secret to validate
            min_length: Minimum required length
            
        Returns:
            True if secret meets requirements
        """
        if len(secret) < min_length:
            return False
        
        # Check for complexity (at least 3 character types)
        has_lower = any(c.islower() for c in secret)
        has_upper = any(c.isupper() for c in secret)
        has_digit = any(c.isdigit() for c in secret)
        has_special = any(not c.isalnum() for c in secret)
        
        complexity = sum([has_lower, has_upper, has_digit, has_special])
        return complexity >= 3


class InputValidator:
    """
    Validates and sanitizes user inputs to prevent injection attacks.
    """
    
    # Patterns for validation
    ALPHANUMERIC = re.compile(r'^[a-zA-Z0-9]+$')
    ALPHANUMERIC_EXTENDED = re.compile(r'^[a-zA-Z0-9_-]+$')
    EMAIL = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    UUID = re.compile(
        r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
        re.IGNORECASE,
    )
    
    # Dangerous patterns to block
    SQL_INJECTION = re.compile(
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE)\b|OR\s+\d+\s*=\s*\d+)",
        re.IGNORECASE,
    )
    XSS_PATTERNS = re.compile(r'<script|javascript:|onerror=|onload=', re.IGNORECASE)
    
    @staticmethod
    def validate_alphanumeric(value: str, allow_extended: bool = False) -> bool:
        """
        Validate alphanumeric input.
        
        Args:
            value: Input to validate
            allow_extended: Allow underscore and dash
            
        Returns:
            True if valid
        """
        if not value:
            return False
        
        pattern = (
            InputValidator.ALPHANUMERIC_EXTENDED
            if allow_extended
            else InputValidator.ALPHANUMERIC
        )
        return bool(pattern.match(value))
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate email format"""
        if not email:
            return False
        return bool(InputValidator.EMAIL.match(email))
    
    @staticmethod
    def validate_uuid(uuid_str: str) -> bool:
        """Validate UUID format"""
        if not uuid_str:
            return False
        return bool(InputValidator.UUID.match(uuid_str))
    
    @staticmethod
    def sanitize_string(
        value: str,
        max_length: int = 1000,
        strip_html: bool = True,
    ) -> str:
        """
        Sanitize string input.
        
        Args:
            value: String to sanitize
            max_length: Maximum allowed length
            strip_html: Remove HTML tags
            
        Returns:
            Sanitized string
        """
        if not value:
            return ""
        
        # Truncate to max length
        value = value[:max_length]
        
        # Strip leading/trailing whitespace
        value = value.strip()
        
        # Remove HTML tags if requested
        if strip_html:
            value = re.sub(r'<[^>]+>', '', value)
        
        return value
    
    @staticmethod
    def check_sql_injection(value: str) -> bool:
        """
        Check if input contains SQL injection patterns.
        
        Returns:
            True if suspicious patterns found
        """
        return bool(InputValidator.SQL_INJECTION.search(value))
    
    @staticmethod
    def check_xss(value: str) -> bool:
        """
        Check if input contains XSS patterns.
        
        Returns:
            True if suspicious patterns found
        """
        return bool(InputValidator.XSS_PATTERNS.search(value))
    
    @staticmethod
    def validate_safe_input(value: str, max_length: int = 1000) -> bool:
        """
        Comprehensive safety check for user input.
        
        Returns:
            True if input is safe
        """
        if not value:
            return True
        
        if len(value) > max_length:
            return False
        
        if InputValidator.check_sql_injection(value):
            return False
        
        if InputValidator.check_xss(value):
            return False
        
        return True


@dataclass
class RateLimitEntry:
    """Rate limit tracking entry"""
    count: int
    window_start: datetime
    
    def is_expired(self, window_seconds: int) -> bool:
        """Check if this entry's window has expired"""
        return datetime.utcnow() > self.window_start + timedelta(seconds=window_seconds)
    
    def reset(self) -> None:
        """Reset the counter and window"""
        self.count = 0
        self.window_start = datetime.utcnow()


class RateLimiter:
    """
    Simple rate limiter for API and operation throttling.
    
    Uses a sliding window algorithm.
    """
    
    def __init__(
        self,
        max_requests: int = 100,
        window_seconds: int = 60,
    ) -> None:
        """
        Initialize rate limiter.
        
        Args:
            max_requests: Maximum requests per window
            window_seconds: Time window in seconds
        """
        self._max_requests = max_requests
        self._window_seconds = window_seconds
        self._entries: Dict[str, RateLimitEntry] = {}
    
    def check_rate_limit(self, identifier: str) -> bool:
        """
        Check if identifier has exceeded rate limit.
        
        Args:
            identifier: Unique identifier (e.g., user_id, IP address)
            
        Returns:
            True if within limit, False if exceeded
        """
        now = datetime.utcnow()
        
        # Get or create entry
        if identifier not in self._entries:
            self._entries[identifier] = RateLimitEntry(
                count=0,
                window_start=now,
            )
        
        entry = self._entries[identifier]
        
        # Check if window has expired
        if entry.is_expired(self._window_seconds):
            entry.reset()
        
        # Check limit
        if entry.count >= self._max_requests:
            return False
        
        # Increment counter
        entry.count += 1
        return True
    
    def get_remaining(self, identifier: str) -> int:
        """Get remaining requests for identifier"""
        if identifier not in self._entries:
            return self._max_requests
        
        entry = self._entries[identifier]
        if entry.is_expired(self._window_seconds):
            return self._max_requests
        
        return max(0, self._max_requests - entry.count)
    
    def reset(self, identifier: str) -> None:
        """Reset rate limit for identifier"""
        if identifier in self._entries:
            self._entries[identifier].reset()


def hash_sensitive_data(data: str, salt: Optional[str] = None) -> str:
    """
    Hash sensitive data for storage (e.g., PII).
    
    Args:
        data: Data to hash
        salt: Optional salt (should be stored separately)
        
    Returns:
        Hexadecimal hash string
    """
    if salt:
        data = f"{data}{salt}"
    return hashlib.sha256(data.encode()).hexdigest()
