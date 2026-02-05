"""
End-to-end integration tests for Mem0 Governance Gateway.

Tests the full request flow through real Docker services:
  Client → Gateway (9000) → OPA (9001) → Audit DB (9005)

These tests validate:
- RBAC authorization via OPA policies
- Audit logging to PostgreSQL
- Rate limiting enforcement
- Request validation pipeline
- Tenant isolation

Requirements:
- Docker stack must be running: cd docker && docker compose up -d
- Services: Gateway (9000), OPA (9001), Audit DB (9005)
- Mem0 backend (9006) is NOT required (503 responses are expected)

Run with: python3 -m pytest test_integration.py -v
"""

import pytest
import httpx


# Gateway endpoint
GATEWAY_URL = "http://localhost:9000"


@pytest.mark.integration
class TestE2ERequestFlow:
    """
    Test end-to-end request flows for different RBAC roles.

    Validates that:
    - Admin can perform all operations (read/write/delete)
    - Reader can only read
    - Writer can read and write
    - Auditor cannot access memory operations
    - All requests are audited with correct decision
    """

    def test_e2e_admin_read_allowed(self, db_connection, admin_headers):
        """Admin read request should be allowed and audited."""
        response = httpx.get(f"{GATEWAY_URL}/memories", headers=admin_headers)

        # Mem0 is down, but Gateway allows request (503 = allowed but backend unavailable)
        assert response.status_code == 503

        # Verify audit log
        cursor = db_connection.cursor()
        cursor.execute("""
            SELECT decision, action, actor_role FROM mem0_audit_log
            WHERE actor_id = %s
            ORDER BY timestamp DESC LIMIT 1
        """, ("admin-user-1",))

        result = cursor.fetchone()
        assert result is not None
        assert result[0] == "allow"
        assert result[1] == "read"
        assert result[2] == "admin"
        cursor.close()

    def test_e2e_reader_denied_write(self, db_connection, reader_headers):
        """Reader write request should be denied and audited."""
        response = httpx.post(
            f"{GATEWAY_URL}/memories",
            headers=reader_headers,
            json={"text": "test memory"}
        )

        assert response.status_code == 403
        assert "Access denied" in response.json()["error"]

        # Verify audit log
        cursor = db_connection.cursor()
        cursor.execute("""
            SELECT decision, action FROM mem0_audit_log
            WHERE actor_id = %s
            ORDER BY timestamp DESC LIMIT 1
        """, ("reader-user-1",))

        result = cursor.fetchone()
        assert result is not None
        assert result[0] == "deny"
        assert result[1] == "write"
        cursor.close()

    def test_e2e_writer_allowed_write(self, db_connection, writer_headers):
        """Writer write request should be allowed and audited."""
        response = httpx.post(
            f"{GATEWAY_URL}/memories",
            headers=writer_headers,
            json={"text": "test memory"}
        )

        # Mem0 is down, but Gateway allows request
        assert response.status_code == 503

        # Verify audit log
        cursor = db_connection.cursor()
        cursor.execute("""
            SELECT decision, action, actor_role FROM mem0_audit_log
            WHERE actor_id = %s
            ORDER BY timestamp DESC LIMIT 1
        """, ("writer-user-1",))

        result = cursor.fetchone()
        assert result is not None
        assert result[0] == "allow"
        assert result[1] == "write"
        assert result[2] == "agent-writer"
        cursor.close()

    def test_e2e_admin_allowed_delete(self, db_connection, admin_headers):
        """Admin delete request should be allowed and audited."""
        response = httpx.delete(
            f"{GATEWAY_URL}/memories/test-id",
            headers=admin_headers
        )

        # Mem0 is down, but Gateway allows request
        assert response.status_code == 503

        # Verify audit log
        cursor = db_connection.cursor()
        cursor.execute("""
            SELECT decision, action FROM mem0_audit_log
            WHERE actor_id = %s
            ORDER BY timestamp DESC LIMIT 1
        """, ("admin-user-1",))

        result = cursor.fetchone()
        assert result is not None
        assert result[0] == "allow"
        assert result[1] == "delete"
        cursor.close()

    def test_e2e_auditor_denied_read(self, db_connection, auditor_headers):
        """Auditor read request should be denied (no memory access)."""
        response = httpx.get(
            f"{GATEWAY_URL}/memories",
            headers=auditor_headers
        )

        assert response.status_code == 403

        # Verify audit log
        cursor = db_connection.cursor()
        cursor.execute("""
            SELECT decision, actor_role FROM mem0_audit_log
            WHERE actor_id = %s
            ORDER BY timestamp DESC LIMIT 1
        """, ("auditor-user-1",))

        result = cursor.fetchone()
        assert result is not None
        assert result[0] == "deny"
        assert result[1] == "auditor"
        cursor.close()


@pytest.mark.integration
class TestE2EValidationAndRateLimiting:
    """
    Test request validation and rate limiting with real state.

    Validates:
    - Missing headers return 400
    - Invalid JSON returns 400
    - Rate limits are enforced
    - Admin gets higher rate limit
    - Retry-After header is set correctly
    """

    def test_e2e_missing_headers(self, db_connection):
        """Request with missing required headers should be rejected."""
        headers = {"X-User-Id": "test-user"}  # Missing X-User-Role and X-Tenant-Id

        response = httpx.get(f"{GATEWAY_URL}/memories", headers=headers)

        assert response.status_code == 400
        assert "Missing required header" in response.json()["error"]

        # Verify audit log
        cursor = db_connection.cursor()
        cursor.execute("""
            SELECT decision FROM mem0_audit_log
            WHERE actor_id = %s
            ORDER BY timestamp DESC LIMIT 1
        """, ("test-user",))

        result = cursor.fetchone()
        assert result is not None
        assert result[0] == "invalid_request"
        cursor.close()

    def test_e2e_rate_limit_enforcement(self, db_connection, reader_headers):
        """Rate limit should be enforced after exceeding quota."""
        # Default rate limit is 100 requests per 60 seconds
        # Make requests until we hit rate limit

        rate_limited = False
        for i in range(105):  # Try up to 105 requests
            response = httpx.get(f"{GATEWAY_URL}/memories", headers=reader_headers)
            if response.status_code == 429:
                rate_limited = True
                assert "Retry-After" in response.headers
                assert int(response.headers["Retry-After"]) > 0
                break
            # Either allowed (503) or denied (403) - both consume rate limit
            assert response.status_code in [403, 503]

        assert rate_limited, "Expected to hit rate limit within 105 requests"

        # Verify audit log for rate_limited decision
        cursor = db_connection.cursor()
        cursor.execute("""
            SELECT decision FROM mem0_audit_log
            WHERE actor_id = %s AND decision = 'rate_limited'
            ORDER BY timestamp DESC LIMIT 1
        """, ("reader-user-1",))

        result = cursor.fetchone()
        assert result is not None
        assert result[0] == "rate_limited"
        cursor.close()

    def test_e2e_admin_higher_rate_limit(self, db_connection, admin_headers):
        """Admin should have higher rate limit (500 vs 100)."""
        # Make 101 requests - admin should not be rate limited yet
        for i in range(101):
            response = httpx.get(f"{GATEWAY_URL}/memories", headers=admin_headers)
            assert response.status_code in [403, 503]  # Not rate limited

        # Verify no rate_limited audit logs for admin
        cursor = db_connection.cursor()
        cursor.execute("""
            SELECT COUNT(*) FROM mem0_audit_log
            WHERE actor_id = %s AND decision = 'rate_limited'
        """, ("admin-user-1",))

        count = cursor.fetchone()[0]
        assert count == 0
        cursor.close()

    def test_e2e_invalid_json_body(self, db_connection, writer_headers):
        """Request with invalid JSON should be rejected."""
        # Add Content-Type header so it passes content-type validation
        writer_headers["Content-Type"] = "application/json"

        response = httpx.post(
            f"{GATEWAY_URL}/memories",
            headers=writer_headers,
            content=b"{invalid json}"
        )

        assert response.status_code == 400
        assert "Invalid JSON" in response.json()["error"]

        # Verify audit log
        cursor = db_connection.cursor()
        cursor.execute("""
            SELECT decision FROM mem0_audit_log
            WHERE actor_id = %s
            ORDER BY timestamp DESC LIMIT 1
        """, ("writer-user-1",))

        result = cursor.fetchone()
        assert result is not None
        assert result[0] == "invalid_request"
        cursor.close()


@pytest.mark.integration
class TestE2ETenantIsolation:
    """
    Test tenant isolation in authorization and rate limiting.

    Validates:
    - Same-tenant users can access resources
    - Admin can access cross-tenant resources
    - Different tenants have independent rate limits
    """

    def test_e2e_same_tenant_users_allowed(self, db_connection):
        """Users in same tenant should both be allowed."""
        tenant1_reader = {
            "X-User-Id": "reader-same-tenant-1",
            "X-User-Role": "agent-reader",
            "X-Tenant-Id": "tenant-same-1"
        }
        tenant1_writer = {
            "X-User-Id": "writer-same-tenant-1",
            "X-User-Role": "agent-writer",
            "X-Tenant-Id": "tenant-same-1"
        }

        # Both should be allowed
        response1 = httpx.get(f"{GATEWAY_URL}/memories", headers=tenant1_reader)
        response2 = httpx.post(
            f"{GATEWAY_URL}/memories",
            headers=tenant1_writer,
            json={"text": "test"}
        )

        assert response1.status_code == 503  # Allowed
        assert response2.status_code == 503  # Allowed

        # Verify both audited as allow
        cursor = db_connection.cursor()
        cursor.execute("""
            SELECT COUNT(*) FROM mem0_audit_log
            WHERE actor_id IN ('reader-same-tenant-1', 'writer-same-tenant-1') AND decision = 'allow'
        """)

        count = cursor.fetchone()[0]
        assert count == 2
        cursor.close()

    def test_e2e_admin_cross_tenant_access(self, db_connection):
        """Admin should be able to access resources across tenants."""
        tenant1_admin = {
            "X-User-Id": "admin-1",
            "X-User-Role": "admin",
            "X-Tenant-Id": "tenant-1"
        }
        tenant2_admin = {
            "X-User-Id": "admin-2",
            "X-User-Role": "admin",
            "X-Tenant-Id": "tenant-2"
        }

        # Both admins should be allowed
        response1 = httpx.get(f"{GATEWAY_URL}/memories", headers=tenant1_admin)
        response2 = httpx.get(f"{GATEWAY_URL}/memories", headers=tenant2_admin)

        assert response1.status_code == 503  # Allowed
        assert response2.status_code == 503  # Allowed

        # Verify both audited
        cursor = db_connection.cursor()
        cursor.execute("""
            SELECT tenant_id, decision FROM mem0_audit_log
            WHERE actor_id IN ('admin-1', 'admin-2')
            ORDER BY timestamp
        """)

        results = cursor.fetchall()
        assert len(results) == 2
        assert results[0][0] == "tenant-1"
        assert results[0][1] == "allow"
        assert results[1][0] == "tenant-2"
        assert results[1][1] == "allow"
        cursor.close()

    def test_e2e_independent_tenant_rate_limits(self, db_connection):
        """Different tenants should have independent rate limit buckets."""
        tenant1_user = {
            "X-User-Id": "user-1",
            "X-User-Role": "agent-reader",
            "X-Tenant-Id": "tenant-1"
        }
        tenant2_user = {
            "X-User-Id": "user-1",  # Same user ID
            "X-User-Role": "agent-reader",
            "X-Tenant-Id": "tenant-2"  # Different tenant
        }

        # Make 100 requests from tenant-1
        for i in range(100):
            httpx.get(f"{GATEWAY_URL}/memories", headers=tenant1_user)

        # Next request from tenant-1 should be rate limited
        response1 = httpx.get(f"{GATEWAY_URL}/memories", headers=tenant1_user)
        assert response1.status_code == 429

        # But tenant-2 should still be allowed
        response2 = httpx.get(f"{GATEWAY_URL}/memories", headers=tenant2_user)
        assert response2.status_code in [403, 503]  # Not rate limited

        # Verify rate limiting is per tenant
        cursor = db_connection.cursor()
        cursor.execute("""
            SELECT tenant_id, decision FROM mem0_audit_log
            WHERE actor_id = 'user-1' AND decision = 'rate_limited'
        """)

        results = cursor.fetchall()
        assert len(results) == 1
        assert results[0][0] == "tenant-1"
        cursor.close()


@pytest.mark.integration
class TestE2ERBACAuthorization:
    """
    Test RBAC authorization enforcement via OPA.

    Validates:
    - All roles have correct read permissions
    - Write permissions limited to admin/writer
    - Delete permissions limited to admin
    - Auditor denied all memory operations
    """

    def test_e2e_read_permissions_by_role(self, db_connection):
        """Test read permissions for all roles."""
        roles_with_read = [
            ("admin-read-perm", "admin"),
            ("reader-read-perm", "agent-reader"),
            ("writer-read-perm", "agent-writer")
        ]
        roles_without_read = [
            ("auditor-read-perm", "auditor")
        ]

        # Test roles with read access
        for user_id, role in roles_with_read:
            headers = {
                "X-User-Id": user_id,
                "X-User-Role": role,
                "X-Tenant-Id": "tenant-read-perm"
            }
            response = httpx.get(f"{GATEWAY_URL}/memories", headers=headers)
            assert response.status_code == 503, f"{role} should be allowed to read"

        # Test roles without read access
        for user_id, role in roles_without_read:
            headers = {
                "X-User-Id": user_id,
                "X-User-Role": role,
                "X-Tenant-Id": "tenant-read-perm"
            }
            response = httpx.get(f"{GATEWAY_URL}/memories", headers=headers)
            assert response.status_code == 403, f"{role} should be denied read"

        cursor = db_connection.cursor()
        cursor.execute("""
            SELECT actor_role, decision FROM mem0_audit_log
            WHERE actor_id IN ('admin-read-perm', 'reader-read-perm', 'writer-read-perm', 'auditor-read-perm')
            ORDER BY timestamp
        """)
        results = cursor.fetchall()
        cursor.close()

        # Verify all logged correctly
        assert len(results) == 4

    def test_e2e_write_permissions_by_role(self, db_connection):
        """Test write permissions for all roles."""
        roles_with_write = [
            ("admin-user", "admin"),
            ("writer-user", "agent-writer")
        ]
        roles_without_write = [
            ("reader-user", "agent-reader"),
            ("auditor-user", "auditor")
        ]

        # Test roles with write access
        for user_id, role in roles_with_write:
            headers = {
                "X-User-Id": user_id,
                "X-User-Role": role,
                "X-Tenant-Id": "tenant-1"
            }
            response = httpx.post(
                f"{GATEWAY_URL}/memories",
                headers=headers,
                json={"text": "test"}
            )
            assert response.status_code == 503, f"{role} should be allowed to write"

        # Test roles without write access
        for user_id, role in roles_without_write:
            headers = {
                "X-User-Id": user_id,
                "X-User-Role": role,
                "X-Tenant-Id": "tenant-1"
            }
            response = httpx.post(
                f"{GATEWAY_URL}/memories",
                headers=headers,
                json={"text": "test"}
            )
            assert response.status_code == 403, f"{role} should be denied write"

    def test_e2e_delete_permissions_by_role(self, db_connection):
        """Test delete permissions - only admin should be allowed."""
        admin_headers = {
            "X-User-Id": "admin-delete-test",
            "X-User-Role": "admin",
            "X-Tenant-Id": "tenant-delete-test"
        }
        reader_headers = {
            "X-User-Id": "reader-delete-test",
            "X-User-Role": "agent-reader",
            "X-Tenant-Id": "tenant-delete-test"
        }
        writer_headers = {
            "X-User-Id": "writer-delete-test",
            "X-User-Role": "agent-writer",
            "X-Tenant-Id": "tenant-delete-test"
        }

        # Admin should be allowed
        response = httpx.delete(f"{GATEWAY_URL}/memories/test", headers=admin_headers)
        assert response.status_code == 503

        # Reader and Writer should be denied
        response = httpx.delete(f"{GATEWAY_URL}/memories/test", headers=reader_headers)
        assert response.status_code == 403

        response = httpx.delete(f"{GATEWAY_URL}/memories/test", headers=writer_headers)
        assert response.status_code == 403

        # Verify audit decisions for these specific users
        cursor = db_connection.cursor()
        cursor.execute("""
            SELECT actor_role, decision FROM mem0_audit_log
            WHERE action = 'delete'
              AND actor_id IN ('admin-delete-test', 'reader-delete-test', 'writer-delete-test')
            ORDER BY timestamp
        """)
        results = cursor.fetchall()
        cursor.close()

        assert len(results) == 3
        assert results[0] == ("admin", "allow")
        assert results[1] == ("agent-reader", "deny")
        assert results[2] == ("agent-writer", "deny")

    def test_e2e_auditor_denied_all_operations(self, db_connection, auditor_headers):
        """Auditor should be denied all memory operations."""
        # Try read
        response = httpx.get(f"{GATEWAY_URL}/memories", headers=auditor_headers)
        assert response.status_code == 403

        # Try write
        response = httpx.post(
            f"{GATEWAY_URL}/memories",
            headers=auditor_headers,
            json={"text": "test"}
        )
        assert response.status_code == 403

        # Try delete
        response = httpx.delete(f"{GATEWAY_URL}/memories/test", headers=auditor_headers)
        assert response.status_code == 403

        # Verify all denied
        cursor = db_connection.cursor()
        cursor.execute("""
            SELECT COUNT(*) FROM mem0_audit_log
            WHERE actor_id = 'auditor-user-1' AND decision = 'deny'
        """)
        count = cursor.fetchone()[0]
        assert count == 3
        cursor.close()


@pytest.mark.integration
class TestE2EAuditLogVerification:
    """
    Test audit log completeness and accuracy.

    Validates:
    - All required fields are populated
    - All decision types are logged correctly
    - Timestamps are accurate
    - Logs are queryable by various fields
    """

    def test_e2e_audit_fields_populated(self, db_connection, admin_headers):
        """All audit log fields should be populated correctly."""
        response = httpx.get(f"{GATEWAY_URL}/memories", headers=admin_headers)
        assert response.status_code == 503

        cursor = db_connection.cursor()
        cursor.execute("""
            SELECT id, timestamp, actor_id, actor_role, tenant_id,
                   action, resource_id, decision, source_ip
            FROM mem0_audit_log
            WHERE actor_id = 'admin-user-1'
            ORDER BY timestamp DESC LIMIT 1
        """)

        result = cursor.fetchone()
        cursor.close()

        assert result is not None
        assert result[0] is not None  # id (UUID)
        assert result[1] is not None  # timestamp
        assert result[2] == "admin-user-1"  # actor_id
        assert result[3] == "admin"  # actor_role
        assert result[4] == "tenant-1"  # tenant_id
        assert result[5] == "read"  # action
        assert result[6] == "memories"  # resource_id
        assert result[7] == "allow"  # decision
        assert result[8] is not None  # source_ip

    def test_e2e_all_decision_types_logged(self, db_connection):
        """All decision types should be logged correctly."""
        # allow
        admin_headers = {
            "X-User-Id": "admin-1",
            "X-User-Role": "admin",
            "X-Tenant-Id": "tenant-1"
        }
        httpx.get(f"{GATEWAY_URL}/memories", headers=admin_headers)

        # deny
        reader_headers = {
            "X-User-Id": "reader-1",
            "X-User-Role": "agent-reader",
            "X-Tenant-Id": "tenant-1"
        }
        httpx.post(f"{GATEWAY_URL}/memories", headers=reader_headers, json={"text": "test"})

        # invalid_request
        httpx.get(f"{GATEWAY_URL}/memories", headers={"X-User-Id": "user-1"})

        # rate_limited (make 100 requests first)
        rate_test_headers = {
            "X-User-Id": "rate-test",
            "X-User-Role": "agent-reader",
            "X-Tenant-Id": "tenant-rate"
        }
        for i in range(101):
            httpx.get(f"{GATEWAY_URL}/memories", headers=rate_test_headers)

        # Verify all decision types exist
        cursor = db_connection.cursor()
        cursor.execute("""
            SELECT DISTINCT decision FROM mem0_audit_log
            ORDER BY decision
        """)
        decisions = [row[0] for row in cursor.fetchall()]
        cursor.close()

        assert "allow" in decisions
        assert "deny" in decisions
        assert "invalid_request" in decisions
        assert "rate_limited" in decisions

    def test_e2e_timeline_accuracy(self, db_connection, admin_headers):
        """Timestamps should increase monotonically."""
        import time

        # Make 3 requests with delays
        httpx.get(f"{GATEWAY_URL}/memories", headers=admin_headers)
        time.sleep(0.1)
        httpx.get(f"{GATEWAY_URL}/memories", headers=admin_headers)
        time.sleep(0.1)
        httpx.get(f"{GATEWAY_URL}/memories", headers=admin_headers)

        cursor = db_connection.cursor()
        cursor.execute("""
            SELECT timestamp FROM mem0_audit_log
            WHERE actor_id = 'admin-user-1'
            ORDER BY timestamp
        """)
        timestamps = [row[0] for row in cursor.fetchall()]
        cursor.close()

        assert len(timestamps) == 3
        assert timestamps[0] < timestamps[1] < timestamps[2]

    def test_e2e_audit_queryable_by_fields(self, db_connection):
        """Audit logs should be queryable by actor, tenant, decision."""
        # Create diverse audit trail with unique IDs
        users = [
            ("user-a-queryable", "admin", "tenant-queryable-1"),
            ("user-b-queryable", "agent-reader", "tenant-queryable-1"),
            ("user-c-queryable", "agent-writer", "tenant-queryable-2")
        ]

        for user_id, role, tenant in users:
            headers = {
                "X-User-Id": user_id,
                "X-User-Role": role,
                "X-Tenant-Id": tenant
            }
            httpx.get(f"{GATEWAY_URL}/memories", headers=headers)

        cursor = db_connection.cursor()

        # Query by actor
        cursor.execute("SELECT COUNT(*) FROM mem0_audit_log WHERE actor_id = 'user-a-queryable'")
        assert cursor.fetchone()[0] == 1

        # Query by tenant
        cursor.execute("SELECT COUNT(*) FROM mem0_audit_log WHERE tenant_id = 'tenant-queryable-1'")
        assert cursor.fetchone()[0] == 2

        # Query by decision for these specific users
        cursor.execute("""
            SELECT COUNT(*) FROM mem0_audit_log
            WHERE decision = 'allow'
              AND actor_id IN ('user-a-queryable', 'user-b-queryable', 'user-c-queryable')
        """)
        assert cursor.fetchone()[0] >= 2

        cursor.close()

    def test_e2e_multiple_requests_logged_separately(self, db_connection, admin_headers):
        """Multiple requests from same user should be logged separately."""
        # Make 5 requests
        for i in range(5):
            httpx.get(f"{GATEWAY_URL}/memories", headers=admin_headers)

        cursor = db_connection.cursor()
        cursor.execute("""
            SELECT COUNT(*) FROM mem0_audit_log
            WHERE actor_id = 'admin-user-1'
        """)
        count = cursor.fetchone()[0]
        cursor.close()

        assert count == 5
