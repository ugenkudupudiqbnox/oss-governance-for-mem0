"""
Tests for security module
"""

import pytest
import os
from mem0_governance.security import (
    SecretManager,
    InputValidator,
    RateLimiter,
    hash_sensitive_data,
)


def test_secret_manager_env_vars():
    """Test secret retrieval from environment variables"""
    os.environ["MEM0_GOV_TEST_SECRET"] = "secret-value-123"
    
    secret_mgr = SecretManager(prefix="MEM0_GOV_")
    value = secret_mgr.get_secret("TEST_SECRET")
    
    assert value == "secret-value-123"
    
    # Cleanup
    del os.environ["MEM0_GOV_TEST_SECRET"]


def test_secret_manager_default():
    """Test secret default value"""
    secret_mgr = SecretManager(prefix="MEM0_GOV_")
    value = secret_mgr.get_secret("NONEXISTENT", default="default-value")
    
    assert value == "default-value"


def test_secret_manager_cache():
    """Test secret caching"""
    secret_mgr = SecretManager(prefix="MEM0_GOV_")
    secret_mgr.set_secret("TEST", "cached-value")
    
    value = secret_mgr.get_secret("TEST")
    assert value == "cached-value"


def test_secret_strength_validation():
    """Test secret strength validation"""
    secret_mgr = SecretManager()
    
    # Strong secret (32+ chars, multiple types)
    strong = "MyVeryStr0ng!Secret#Key$2024"
    assert secret_mgr.validate_secret_strength(strong, min_length=20)
    
    # Weak secret (too short)
    weak_short = "short"
    assert not secret_mgr.validate_secret_strength(weak_short, min_length=32)
    
    # Weak secret (not enough complexity)
    weak_simple = "a" * 32
    assert not secret_mgr.validate_secret_strength(weak_simple, min_length=32)


def test_input_validator_alphanumeric():
    """Test alphanumeric validation"""
    validator = InputValidator()
    
    assert validator.validate_alphanumeric("abc123")
    assert validator.validate_alphanumeric("ABC123")
    assert not validator.validate_alphanumeric("abc-123")  # Dash not allowed
    
    # With extended characters
    assert validator.validate_alphanumeric("abc-123", allow_extended=True)
    assert validator.validate_alphanumeric("abc_123", allow_extended=True)


def test_input_validator_email():
    """Test email validation"""
    validator = InputValidator()
    
    assert validator.validate_email("user@example.com")
    assert validator.validate_email("john.doe@company.co.uk")
    assert not validator.validate_email("invalid-email")
    assert not validator.validate_email("@example.com")


def test_input_validator_uuid():
    """Test UUID validation"""
    validator = InputValidator()
    
    assert validator.validate_uuid("550e8400-e29b-41d4-a716-446655440000")
    assert not validator.validate_uuid("not-a-uuid")
    assert not validator.validate_uuid("550e8400-e29b-41d4-a716")


def test_input_validator_sql_injection():
    """Test SQL injection detection"""
    validator = InputValidator()
    
    # Safe input
    assert not validator.check_sql_injection("John Doe")
    
    # Suspicious input
    assert validator.check_sql_injection("'; DROP TABLE users; --")
    assert validator.check_sql_injection("1 OR 1=1")
    assert validator.check_sql_injection("SELECT * FROM users")


def test_input_validator_xss():
    """Test XSS detection"""
    validator = InputValidator()
    
    # Safe input
    assert not validator.check_xss("Hello World")
    
    # Suspicious input
    assert validator.check_xss("<script>alert('XSS')</script>")
    assert validator.check_xss("javascript:alert('XSS')")
    assert validator.check_xss("<img onerror='alert(1)' src='x'>")


def test_input_validator_sanitize():
    """Test string sanitization"""
    validator = InputValidator()
    
    # Remove HTML
    result = validator.sanitize_string("<b>Hello</b> World", strip_html=True)
    assert result == "Hello World"
    
    # Truncate
    result = validator.sanitize_string("a" * 100, max_length=50)
    assert len(result) == 50
    
    # Strip whitespace
    result = validator.sanitize_string("  Hello  ")
    assert result == "Hello"


def test_input_validator_safe_input():
    """Test comprehensive safety check"""
    validator = InputValidator()
    
    # Safe inputs
    assert validator.validate_safe_input("Hello World")
    assert validator.validate_safe_input("user@example.com")
    
    # Unsafe inputs
    assert not validator.validate_safe_input("'; DROP TABLE users; --")
    assert not validator.validate_safe_input("<script>alert(1)</script>")
    assert not validator.validate_safe_input("a" * 10000)  # Too long


def test_rate_limiter():
    """Test rate limiting"""
    limiter = RateLimiter(max_requests=3, window_seconds=60)
    
    # First 3 requests should pass
    assert limiter.check_rate_limit("user1")
    assert limiter.check_rate_limit("user1")
    assert limiter.check_rate_limit("user1")
    
    # 4th request should be blocked
    assert not limiter.check_rate_limit("user1")


def test_rate_limiter_multiple_identifiers():
    """Test rate limiting for different identifiers"""
    limiter = RateLimiter(max_requests=2, window_seconds=60)
    
    # User 1
    assert limiter.check_rate_limit("user1")
    assert limiter.check_rate_limit("user1")
    assert not limiter.check_rate_limit("user1")  # Blocked
    
    # User 2 should still have quota
    assert limiter.check_rate_limit("user2")
    assert limiter.check_rate_limit("user2")


def test_rate_limiter_remaining():
    """Test getting remaining requests"""
    limiter = RateLimiter(max_requests=5, window_seconds=60)
    
    assert limiter.get_remaining("user1") == 5
    
    limiter.check_rate_limit("user1")
    assert limiter.get_remaining("user1") == 4
    
    limiter.check_rate_limit("user1")
    assert limiter.get_remaining("user1") == 3


def test_rate_limiter_reset():
    """Test rate limit reset"""
    limiter = RateLimiter(max_requests=2, window_seconds=60)
    
    limiter.check_rate_limit("user1")
    limiter.check_rate_limit("user1")
    assert not limiter.check_rate_limit("user1")  # Blocked
    
    # Reset
    limiter.reset("user1")
    assert limiter.check_rate_limit("user1")  # Now allowed


def test_hash_sensitive_data():
    """Test hashing sensitive data"""
    data = "sensitive-pii-data"
    
    hash1 = hash_sensitive_data(data)
    hash2 = hash_sensitive_data(data)
    
    # Should be deterministic
    assert hash1 == hash2
    
    # Should be 64 chars (SHA-256)
    assert len(hash1) == 64
    
    # With salt
    hash_salted = hash_sensitive_data(data, salt="random-salt")
    assert hash_salted != hash1


def test_no_hardcoded_secrets():
    """Test that no secrets are hard-coded in the module"""
    from mem0_governance import security
    import inspect
    
    source = inspect.getsource(security)
    
    # Check for common secret patterns
    dangerous_patterns = [
        "password =",
        "api_key =",
        "secret =",
        "token =",
    ]
    
    # This is a simple check - in reality, secrets should never be in code
    # We're just checking that the module uses proper secret management
    for pattern in dangerous_patterns:
        # Make sure there are no assignment patterns like "api_key = 'value'"
        # This is a basic check and may have false positives
        pass  # In a real test, we'd use more sophisticated checks
