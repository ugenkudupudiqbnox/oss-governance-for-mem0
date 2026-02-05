import time
from unittest.mock import patch, MagicMock

import pytest
from fastapi.testclient import TestClient

import main
from main import app, check_rate_limit, _rate_limit_buckets

client = TestClient(app)

AUTH_HEADERS = {
    "X-User-Id": "user-1",
    "X-User-Role": "agent-reader",
    "X-Tenant-Id": "tenant-1",
}


@pytest.fixture(autouse=True)
def _clear_rate_limits():
    """Reset rate limit state between tests."""
    _rate_limit_buckets.clear()
    yield
    _rate_limit_buckets.clear()


# ---------------------------------------------------------------------------
# Request validation tests
# ---------------------------------------------------------------------------

class TestValidation:
    def test_missing_user_role_returns_400(self):
        resp = client.get("/memories", headers={"X-Tenant-Id": "t1"})
        assert resp.status_code == 400
        assert "X-User-Role" in resp.json()["error"]

    def test_missing_tenant_id_returns_400(self):
        resp = client.get("/memories", headers={"X-User-Role": "agent-reader"})
        assert resp.status_code == 400
        assert "X-Tenant-Id" in resp.json()["error"]

    def test_missing_both_headers_returns_400(self):
        resp = client.get("/memories")
        assert resp.status_code == 400

    def test_path_traversal_blocked(self):
        """Starlette normalizes ../ in URLs, so we test the validator directly."""
        from unittest.mock import AsyncMock
        import asyncio

        mock_request = MagicMock()
        mock_request.headers = {"X-User-Role": "admin", "X-Tenant-Id": "t1"}
        mock_request.method = "GET"

        from main import validate_request
        result = asyncio.get_event_loop().run_until_complete(
            validate_request(mock_request, "foo/../etc/passwd")
        )
        assert result == "Path traversal detected"

    def test_path_traversal_no_false_positive(self):
        """Paths without .. should not be flagged."""
        from unittest.mock import AsyncMock
        import asyncio

        mock_request = MagicMock()
        mock_request.headers = {"X-User-Role": "admin", "X-Tenant-Id": "t1"}
        mock_request.method = "GET"

        from main import validate_request
        result = asyncio.get_event_loop().run_until_complete(
            validate_request(mock_request, "memories/123")
        )
        assert result is None

    @patch("main.log_audit")
    def test_wrong_content_type_post_returns_400(self, mock_audit):
        resp = client.post(
            "/memories",
            headers={**AUTH_HEADERS, "Content-Type": "text/plain"},
            content=b"not json",
        )
        assert resp.status_code == 400
        assert "Content-Type" in resp.json()["error"]

    @patch("main.log_audit")
    def test_wrong_content_type_put_returns_400(self, mock_audit):
        resp = client.put(
            "/memories/1",
            headers={**AUTH_HEADERS, "Content-Type": "text/xml"},
            content=b"<xml/>",
        )
        assert resp.status_code == 400
        assert "Content-Type" in resp.json()["error"]

    @patch("main.log_audit")
    def test_invalid_json_body_returns_400(self, mock_audit):
        resp = client.post(
            "/memories",
            headers={**AUTH_HEADERS, "Content-Type": "application/json"},
            content=b"{invalid json}",
        )
        assert resp.status_code == 400
        assert "Invalid JSON" in resp.json()["error"]

    @patch("main.log_audit")
    def test_oversized_body_returns_400(self, mock_audit):
        original = main.MAX_BODY_SIZE_BYTES
        main.MAX_BODY_SIZE_BYTES = 64
        try:
            resp = client.post(
                "/memories",
                headers={**AUTH_HEADERS, "Content-Type": "application/json"},
                content=b'{"data": "' + b"x" * 100 + b'"}',
            )
            assert resp.status_code == 400
            assert "maximum size" in resp.json()["error"]
        finally:
            main.MAX_BODY_SIZE_BYTES = original

    @patch("main.log_audit")
    @patch("main.check_opa", return_value=True)
    def test_valid_get_passes_validation(self, mock_opa, mock_audit):
        resp = client.get("/memories", headers=AUTH_HEADERS)
        # Should reach OPA/proxy, not be rejected by validation
        assert resp.status_code != 400

    @patch("main.log_audit")
    @patch("main.check_opa", return_value=True)
    def test_valid_post_passes_validation(self, mock_opa, mock_audit):
        resp = client.post(
            "/memories",
            headers={**AUTH_HEADERS, "Content-Type": "application/json"},
            content=b'{"text": "hello"}',
        )
        assert resp.status_code != 400

    @patch("main.log_audit")
    def test_get_no_content_type_check(self, mock_audit):
        """GET requests should not require Content-Type."""
        with patch("main.check_opa", return_value=True):
            resp = client.get("/memories", headers=AUTH_HEADERS)
            assert resp.status_code != 400

    @patch("main.log_audit")
    def test_validation_failure_audited_as_invalid_request(self, mock_audit):
        client.get("/memories", headers={"X-Tenant-Id": "t1"})
        mock_audit.assert_called_once()
        call_args = mock_audit.call_args
        assert call_args[0][5] == "invalid_request"


# ---------------------------------------------------------------------------
# Rate limiting tests
# ---------------------------------------------------------------------------

class TestRateLimiting:
    def test_within_limit_allowed(self):
        allowed, retry = check_rate_limit("t1", "u1", "agent-reader")
        assert allowed is True
        assert retry == 0

    def test_exceeds_limit_denied(self):
        original = main.RATE_LIMIT_REQUESTS
        main.RATE_LIMIT_REQUESTS = 3
        try:
            for _ in range(3):
                allowed, _ = check_rate_limit("t1", "u1", "agent-reader")
                assert allowed is True
            allowed, retry = check_rate_limit("t1", "u1", "agent-reader")
            assert allowed is False
            assert retry >= 1
        finally:
            main.RATE_LIMIT_REQUESTS = original

    def test_admin_gets_higher_limit(self):
        original_std = main.RATE_LIMIT_REQUESTS
        original_admin = main.RATE_LIMIT_ADMIN_REQUESTS
        main.RATE_LIMIT_REQUESTS = 2
        main.RATE_LIMIT_ADMIN_REQUESTS = 5
        try:
            # Standard user hits limit at 2
            for _ in range(2):
                check_rate_limit("t1", "std-user", "agent-reader")
            allowed, _ = check_rate_limit("t1", "std-user", "agent-reader")
            assert allowed is False

            # Admin still allowed at request 3, 4, 5
            for _ in range(5):
                allowed, _ = check_rate_limit("t1", "admin-user", "admin")
                assert allowed is True
            # Admin hits limit at 6
            allowed, _ = check_rate_limit("t1", "admin-user", "admin")
            assert allowed is False
        finally:
            main.RATE_LIMIT_REQUESTS = original_std
            main.RATE_LIMIT_ADMIN_REQUESTS = original_admin

    def test_different_users_independent_limits(self):
        original = main.RATE_LIMIT_REQUESTS
        main.RATE_LIMIT_REQUESTS = 2
        try:
            for _ in range(2):
                check_rate_limit("t1", "user-a", "agent-reader")
            allowed, _ = check_rate_limit("t1", "user-a", "agent-reader")
            assert allowed is False

            # user-b should still be allowed
            allowed, _ = check_rate_limit("t1", "user-b", "agent-reader")
            assert allowed is True
        finally:
            main.RATE_LIMIT_REQUESTS = original

    def test_different_tenants_independent_limits(self):
        original = main.RATE_LIMIT_REQUESTS
        main.RATE_LIMIT_REQUESTS = 2
        try:
            for _ in range(2):
                check_rate_limit("t1", "user-a", "agent-reader")
            allowed, _ = check_rate_limit("t1", "user-a", "agent-reader")
            assert allowed is False

            # Same user in different tenant should be allowed
            allowed, _ = check_rate_limit("t2", "user-a", "agent-reader")
            assert allowed is True
        finally:
            main.RATE_LIMIT_REQUESTS = original

    def test_window_expiry_allows_new_requests(self):
        original_req = main.RATE_LIMIT_REQUESTS
        original_win = main.RATE_LIMIT_WINDOW_SECONDS
        main.RATE_LIMIT_REQUESTS = 2
        main.RATE_LIMIT_WINDOW_SECONDS = 1
        try:
            for _ in range(2):
                check_rate_limit("t1", "u1", "agent-reader")
            allowed, _ = check_rate_limit("t1", "u1", "agent-reader")
            assert allowed is False

            # Wait for window to expire
            time.sleep(1.1)

            allowed, _ = check_rate_limit("t1", "u1", "agent-reader")
            assert allowed is True
        finally:
            main.RATE_LIMIT_REQUESTS = original_req
            main.RATE_LIMIT_WINDOW_SECONDS = original_win

    def test_retry_after_is_positive(self):
        original = main.RATE_LIMIT_REQUESTS
        main.RATE_LIMIT_REQUESTS = 1
        try:
            check_rate_limit("t1", "u1", "agent-reader")
            _, retry = check_rate_limit("t1", "u1", "agent-reader")
            assert retry >= 1
        finally:
            main.RATE_LIMIT_REQUESTS = original

    @patch("main.log_audit")
    def test_rate_limit_returns_429_with_retry_after(self, mock_audit):
        original = main.RATE_LIMIT_REQUESTS
        main.RATE_LIMIT_REQUESTS = 2
        try:
            for _ in range(2):
                with patch("main.check_opa", return_value=True):
                    client.get("/memories", headers=AUTH_HEADERS)

            resp = client.get("/memories", headers=AUTH_HEADERS)
            assert resp.status_code == 429
            assert "Retry-After" in resp.headers
            assert int(resp.headers["Retry-After"]) >= 1
            assert "Rate limit exceeded" in resp.json()["error"]
        finally:
            main.RATE_LIMIT_REQUESTS = original

    @patch("main.log_audit")
    def test_rate_limit_audited_as_rate_limited(self, mock_audit):
        original = main.RATE_LIMIT_REQUESTS
        main.RATE_LIMIT_REQUESTS = 1
        try:
            with patch("main.check_opa", return_value=True):
                client.get("/memories", headers=AUTH_HEADERS)

            client.get("/memories", headers=AUTH_HEADERS)
            # Last call to log_audit should have "rate_limited"
            last_call = mock_audit.call_args_list[-1]
            assert last_call[0][5] == "rate_limited"
        finally:
            main.RATE_LIMIT_REQUESTS = original


# ---------------------------------------------------------------------------
# Integration: validation runs before rate limiting
# ---------------------------------------------------------------------------

class TestRequestFlow:
    @patch("main.log_audit")
    def test_invalid_request_does_not_consume_rate_limit(self, mock_audit):
        original = main.RATE_LIMIT_REQUESTS
        main.RATE_LIMIT_REQUESTS = 2
        try:
            # Send invalid requests (missing headers) — should not count
            for _ in range(5):
                client.get("/memories")

            # Valid request should still be within limit
            with patch("main.check_opa", return_value=True):
                resp = client.get("/memories", headers=AUTH_HEADERS)
            assert resp.status_code != 429
        finally:
            main.RATE_LIMIT_REQUESTS = original

    def test_health_endpoint_no_auth_needed(self):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "healthy"}

    @patch("main.log_audit")
    @patch("main.check_opa", return_value=False)
    def test_opa_deny_returns_403(self, mock_opa, mock_audit):
        resp = client.get("/memories", headers=AUTH_HEADERS)
        assert resp.status_code == 403

    @patch("main.log_audit")
    @patch("main.check_opa", return_value=True)
    def test_allowed_request_audited_as_allow(self, mock_opa, mock_audit):
        resp = client.get("/memories", headers=AUTH_HEADERS)
        last_call = mock_audit.call_args_list[-1]
        assert last_call[0][5] == "allow"
