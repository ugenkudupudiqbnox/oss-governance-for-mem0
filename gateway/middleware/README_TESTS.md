# Gateway Middleware Test Suite

Complete test coverage for the Mem0 Governance Gateway with both unit and integration tests.

## Test Summary

| Test Type | Count | Runtime | Dependencies |
|-----------|-------|---------|--------------|
| **Unit Tests** | 26 | ~3s | None (uses mocks) |
| **Integration Tests** | 21 | ~50s | Docker stack required |
| **OPA Policy Tests** | 3 | ~5s | Docker OPA container |
| **TOTAL** | **50** | **~58s** | |

## Quick Start

### Run All Tests (Unit + Integration)
```bash
cd /opt/oss-governance-for-mem0/gateway/middleware
python3 -m pytest -v
```

### Run Unit Tests Only (Fast, No Docker)
```bash
python3 -m pytest test_main.py -v
```

### Run Integration Tests Only (Requires Docker)
```bash
# Start Docker stack first
cd /opt/oss-governance-for-mem0/docker && docker compose up -d

# Run integration tests
cd /opt/oss-governance-for-mem0/gateway/middleware
python3 -m pytest test_integration.py -v
```

### Run OPA Policy Tests
```bash
docker exec gov_mem0_opa opa test /policies -v
```

## Test Files

```
gateway/middleware/
├── main.py                    # Gateway implementation
├── conftest.py                # Shared fixtures (DB, cleanup, service checks)
├── test_main.py              # Unit tests (26 tests, mocked)
├── test_integration.py       # Integration tests (21 tests, real services)
├── requirements.txt          # Dependencies including pytest
└── README_TESTS.md           # This file
```

## Unit Tests (test_main.py)

**26 tests** validating gateway logic in isolation using mocks.

### Test Classes

1. **TestValidation** (13 tests)
   - Missing required headers (X-User-Role, X-Tenant-Id)
   - Path traversal detection
   - Content-Type validation for POST/PUT/PATCH
   - JSON body validation
   - Body size limits
   - Audit logging of invalid requests

2. **TestRateLimiting** (9 tests)
   - Rate limit enforcement (100 req/60s default)
   - Admin higher limit (500 req/60s)
   - Independent limits per tenant:actor
   - Sliding window expiry
   - Retry-After header correctness
   - Audit logging of rate_limited decisions

3. **TestRequestFlow** (4 tests)
   - Health endpoint accessible without auth
   - Invalid requests don't consume rate limit
   - OPA deny returns 403
   - Allowed requests audited correctly

**Key Features:**
- Uses `unittest.mock` to mock `check_opa` and `log_audit`
- No external dependencies (runs without Docker)
- Fast execution (~3 seconds)
- Clears rate limit state between tests via `autouse` fixture

## Integration Tests (test_integration.py)

**21 tests** validating full request flow through real services.

### Architecture Under Test

```
Test Client → Gateway (9000) → OPA (9001) → Audit DB (9005)
                                ↓
                          Mem0 (9006, unavailable = OK)
```

### Test Classes

1. **TestE2ERequestFlow** (5 tests)
   - Admin can read/write/delete (all allowed)
   - Reader can only read (write denied)
   - Writer can read and write (delete denied)
   - Auditor denied all memory operations
   - All requests audited with correct decision

2. **TestE2EValidationAndRateLimiting** (4 tests)
   - Missing headers return 400 + audit "invalid_request"
   - Rate limit enforced after quota exceeded (429 + Retry-After)
   - Admin gets higher rate limit (500 vs 100)
   - Invalid JSON body returns 400 + audit "invalid_request"

3. **TestE2ETenantIsolation** (3 tests)
   - Same-tenant users can access resources
   - Admin can access cross-tenant resources
   - Different tenants have independent rate limits

4. **TestE2ERBACAuthorization** (4 tests)
   - Read permissions: admin/reader/writer ✓, auditor ✗
   - Write permissions: admin/writer ✓, reader/auditor ✗
   - Delete permissions: admin ✓, others ✗
   - Auditor denied all memory operations

5. **TestE2EAuditLogVerification** (5 tests)
   - All audit fields populated (actor, role, tenant, action, resource, decision, IP, timestamp)
   - All decision types logged (allow, deny, invalid_request, rate_limited)
   - Timestamps increase monotonically
   - Logs queryable by actor, tenant, decision
   - Multiple requests logged separately

**Key Features:**
- Uses real HTTP requests via `httpx` to `http://localhost:9000`
- Validates OPA authorization enforcement
- Verifies PostgreSQL audit log writes
- Timestamp-based audit log cleanup between tests
- Service health checks prevent false failures
- Unique actor/tenant IDs per test to avoid cross-contamination

## Shared Fixtures (conftest.py)

Provides reusable test infrastructure:

### Database Fixtures
- `db_connection`: PostgreSQL connection to audit DB
- `clean_test_audit_logs`: Timestamp-based cleanup (autouse)

### Service Health Checks
- `check_services_running`: Verifies Gateway, OPA, Audit DB before tests
- Retries 3 times with 2-second delays
- Exits pytest with clear error if services unavailable

### Rate Limit Management
- `reset_rate_limit_state`: Clears in-memory buckets between tests (autouse)

### Role Headers
- `admin_headers`: Full access, higher rate limit
- `reader_headers`: Read only, tenant-isolated
- `writer_headers`: Read + write, tenant-isolated
- `auditor_headers`: Audit read only

## Test Coverage

### Features Tested

✅ **Authorization (RBAC)**
- All 4 roles (admin, agent-reader, agent-writer, auditor)
- All 4 actions (read, write, delete, audit_read)
- Tenant isolation enforcement
- OPA policy integration

✅ **Request Validation**
- Required headers (X-User-Role, X-Tenant-Id)
- Path traversal protection
- Content-Type validation
- JSON body validation
- Body size limits

✅ **Rate Limiting**
- Per-tenant, per-actor enforcement
- Role-based limits (admin: 500, others: 100)
- Sliding window expiry
- Retry-After header
- Independent tenant buckets

✅ **Audit Logging**
- All 4 decision types (allow, deny, invalid_request, rate_limited)
- Complete audit trail (actor, role, tenant, action, resource, decision, IP, timestamp)
- PostgreSQL persistence
- Queryability by multiple fields

✅ **Gateway Proxy**
- Request forwarding to Mem0
- 503 handling when backend unavailable
- Header propagation

## Dependencies

### Python Packages (requirements.txt)
```
fastapi==0.109.0
uvicorn==0.27.0
httpx==0.26.0
psycopg2-binary==2.9.9
pytest==8.0.0
```

### Docker Services
- **Gateway** (localhost:9000): FastAPI middleware
- **OPA** (localhost:9001): Policy engine
- **Audit DB** (localhost:9005): PostgreSQL 15
- **Mem0** (localhost:9006): Not required for tests (503 responses expected)

## Troubleshooting

### Integration Tests Fail: "Services not accessible"

**Problem**: Docker services not running or not ready.

**Solution**:
```bash
# Start Docker stack
cd docker && docker compose up -d

# Wait 10-15 seconds for initialization
sleep 15

# Verify services
docker compose ps
curl -s http://localhost:9000/health  # Should return {"status":"healthy"}
```

### Integration Tests Fail: Gateway returns 403/503 on /health

**Problem**: Gateway Docker image is outdated (built before /health endpoint was added).

**Solution**:
```bash
cd docker
docker compose build gateway
docker compose up -d gateway
sleep 5
```

### Audit Log Cleanup Not Working

**Problem**: Tests see logs from previous runs.

**Solution**: Cleanup is timestamp-based and automatic. If you see stale data:
```bash
# Connect to audit DB
docker exec -it gov_mem0_audit_db psql -U audit -d audit

# Manually clean up
DELETE FROM mem0_audit_log WHERE timestamp < NOW() - INTERVAL '1 hour';
```

### Rate Limit Tests Flaky

**Problem**: Rate limit state persists between test runs in the gateway container.

**Solution**: Restart gateway to clear in-memory state:
```bash
docker restart gov_mem0_gateway
sleep 5
```

## Test Execution Times

Measured on AWS EC2 instance:

| Command | Tests | Runtime |
|---------|-------|---------|
| `pytest test_main.py -v` | 26 unit | ~3s |
| `pytest test_integration.py -v` | 21 integration | ~50s |
| `pytest -v` | 47 total | ~53s |

Integration tests are slower due to:
- Real HTTP requests
- OPA policy evaluation
- PostgreSQL writes
- Rate limit enforcement (100+ requests per test)

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Test Gateway

on: [push, pull_request]

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - name: Install dependencies
        run: |
          cd gateway/middleware
          pip install -r requirements.txt
      - name: Run unit tests
        run: |
          cd gateway/middleware
          pytest test_main.py -v

  integration-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Start Docker services
        run: |
          cd docker
          docker compose up -d
          sleep 15
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - name: Install dependencies
        run: |
          cd gateway/middleware
          pip install -r requirements.txt
      - name: Run integration tests
        run: |
          cd gateway/middleware
          pytest test_integration.py -v
      - name: Cleanup
        if: always()
        run: |
          cd docker
          docker compose down -v
```

## Future Enhancements

### Planned Improvements

1. **Performance Tests**
   - Load testing with locust/k6
   - Measure throughput under rate limiting
   - Validate OPA response times

2. **Security Tests**
   - Fuzz testing for request validation
   - SQL injection attempts on audit queries
   - Authorization bypass attempts

3. **Compliance Tests**
   - SOC 2 control validation
   - HIPAA audit log requirements
   - GDPR right-to-access queries

4. **Multi-Instance Tests**
   - Redis-backed rate limiting
   - Distributed audit log writes
   - Load balancer integration

## Related Documentation

- `CLAUDE.md`: Project overview and conventions
- `compliance/controls-mapping.md`: Compliance mappings
- `policies/README.md`: OPA policy documentation
- `audit/schema.sql`: Audit log schema
