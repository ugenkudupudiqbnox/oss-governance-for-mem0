"""
Shared pytest fixtures for gateway middleware tests.

Provides:
- Database connection and cleanup for integration tests
- Service health checks (Gateway, OPA, Audit DB)
- Rate limit state reset between tests
"""

import pytest
import psycopg2
import httpx
import time
from datetime import datetime


@pytest.fixture
def db_connection():
    """
    PostgreSQL connection to audit DB (localhost:9005).

    Yields a connection that's automatically closed after test.
    """
    conn = psycopg2.connect(
        host="localhost",
        port="9005",
        database="audit",
        user="audit",
        password="audit"
    )
    yield conn
    conn.close()


@pytest.fixture(autouse=True)
def clean_test_audit_logs(db_connection):
    """
    Timestamp-based cleanup: delete logs created during test.

    Uses autouse=True to run for every test automatically.
    Records the latest timestamp before test, then deletes any
    logs created after that timestamp.
    """
    cursor = db_connection.cursor()

    # Record the latest timestamp before test runs
    cursor.execute(
        "SELECT COALESCE(MAX(timestamp), '1970-01-01'::timestamptz) FROM mem0_audit_log"
    )
    test_start_time = cursor.fetchone()[0]

    yield  # Run the test

    # Clean up logs created during test
    cursor.execute(
        "DELETE FROM mem0_audit_log WHERE timestamp > %s",
        (test_start_time,)
    )
    db_connection.commit()
    cursor.close()


@pytest.fixture(autouse=True)
def reset_rate_limit_state():
    """
    Clear in-memory rate limit buckets between tests.

    Ensures tests are independent by resetting the rate limiting
    state before and after each test.
    """
    from main import _rate_limit_buckets
    _rate_limit_buckets.clear()
    yield
    _rate_limit_buckets.clear()


@pytest.fixture(scope="session", autouse=True)
def check_services_running():
    """
    Verify Gateway, OPA, and Audit DB are accessible before tests.

    Runs once per test session. Retries each service up to 3 times
    with 2-second delays. If any service is unavailable, pytest exits
    with a clear error message.
    """
    services = {
        "Gateway": {
            "type": "http",
            "url": "http://localhost:9000/memories",
            "headers": {
                "X-User-Role": "admin",
                "X-Tenant-Id": "test"
            },
            "expected_status": [403, 503]  # Either OPA deny or Mem0 unavailable is fine
        },
        "OPA": {
            "type": "http",
            "url": "http://localhost:9001/health",
            "expected_status": [200]
        },
        "Audit DB": {
            "type": "docker_postgres",
            "container": "gov_mem0_audit_db",
            "user": "audit",
            "database": "audit"
        }
    }

    failed_services = []

    for service_name, config in services.items():
        success = False
        last_error = None

        for attempt in range(3):
            try:
                if config["type"] == "http":
                    headers = config.get("headers", {})
                    response = httpx.get(config["url"], headers=headers, timeout=2.0)
                    expected = config["expected_status"]
                    if response.status_code in expected:
                        success = True
                        break
                    else:
                        last_error = f"HTTP {response.status_code} (expected {expected})"

                elif config["type"] == "docker_postgres":
                    import subprocess
                    result = subprocess.run(
                        ["docker", "exec", config["container"], "psql",
                         "-U", config["user"], "-d", config["database"], "-c", "SELECT 1"],
                        capture_output=True,
                        timeout=5
                    )
                    if result.returncode == 0:
                        success = True
                        break
                    else:
                        last_error = f"psql failed: {result.stderr.decode()[:100]}"

            except Exception as e:
                last_error = str(e)

            if attempt < 2:
                time.sleep(2)

        if not success:
            failed_services.append(f"{service_name}: {last_error}")

    if failed_services:
        error_msg = (
            "\n\n" + "="*60 + "\n"
            "INTEGRATION TESTS REQUIRE RUNNING DOCKER SERVICES\n"
            "="*60 + "\n\n"
            "The following services are not accessible:\n"
            + "\n".join(f"  - {svc}" for svc in failed_services)
            + "\n\n"
            "Please start the Docker stack:\n"
            "  cd docker && docker compose up -d\n\n"
            "Then wait 10-15 seconds for services to initialize.\n"
            "="*60 + "\n"
        )
        pytest.exit(error_msg, returncode=1)


@pytest.fixture
def admin_headers():
    """Headers for admin role (full access, higher rate limit)."""
    return {
        "X-User-Id": "admin-user-1",
        "X-User-Role": "admin",
        "X-Tenant-Id": "tenant-1"
    }


@pytest.fixture
def reader_headers():
    """Headers for agent-reader role (read only, tenant-isolated)."""
    return {
        "X-User-Id": "reader-user-1",
        "X-User-Role": "agent-reader",
        "X-Tenant-Id": "tenant-1"
    }


@pytest.fixture
def writer_headers():
    """Headers for agent-writer role (read + write, tenant-isolated)."""
    return {
        "X-User-Id": "writer-user-1",
        "X-User-Role": "agent-writer",
        "X-Tenant-Id": "tenant-1"
    }


@pytest.fixture
def auditor_headers():
    """Headers for auditor role (audit read only)."""
    return {
        "X-User-Id": "auditor-user-1",
        "X-User-Role": "auditor",
        "X-Tenant-Id": "tenant-1"
    }
