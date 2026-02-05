# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Governance Pack for Mem0** is an open-source governance, security, audit, and compliance companion layer for Mem0 (OSS). It enables Mem0 deployments in enterprise and regulated environments (SOC 2, ISO 27001, HIPAA) without modifying Mem0 itself.

This is a **configuration-as-code and documentation project**, not a compiled application. It provides:
- OPA/Rego authorization policies
- Audit logging schemas (PostgreSQL)
- IAM configuration (Keycloak)
- Reference Docker Compose stack
- Compliance documentation and evidence templates

## Commands

### Start Local Governance Stack
```bash
cd docker && docker compose up -d
```

### Run OPA Policy Tests
```bash
opa test policies/ -v
```

### Run Gateway Unit Tests
```bash
cd gateway/middleware && python3 -m pytest test_main.py -v
```

### Run Gateway Integration Tests
```bash
cd gateway/middleware && python3 -m pytest test_integration.py -v
```

### Run All Gateway Tests (Unit + Integration)
```bash
cd gateway/middleware && python3 -m pytest -v
```

### Service Ports (Local Development)
- Gateway (API): http://localhost:9000
- OPA (Policy Engine): http://localhost:9001
- Keycloak (IAM): http://localhost:9002 (admin/admin)
- Grafana (Dashboards): http://localhost:9003
- Loki (Logs): http://localhost:9004
- Audit DB (PostgreSQL): localhost:9005
- Mem0 (Backend): http://localhost:9006

## Architecture

The project operates as a **sidecar/gateway pattern** around Mem0:

```
Client → FastAPI Gateway (9000) → OPA Policy Check (9001) → Mem0 (9006)
                ↓
         Audit Log (PostgreSQL 9005)
                ↓
         Grafana/Loki (9003/9004)
```

**Key Layers:**
1. **IAM** (`iam/keycloak/`): Keycloak OIDC realm with RBAC roles
2. **Policy** (`policies/`): OPA Rego rules for authorization
3. **Audit** (`audit/`): PostgreSQL schema for immutable audit trails
4. **Gateway** (`gateway/middleware/`): FastAPI proxy with OPA auth, rate limiting, request validation, and audit logging
5. **Observability** (`observability/`): Grafana dashboards for audit events

**RBAC Roles:** `admin`, `agent-writer`, `agent-reader`, `auditor`

## Hard Constraints

- **NEVER modify Mem0 source code** - treat it as an external black box
- **Deny-by-default** - all access denied unless explicitly allowed by policy
- **No hard-coded secrets** - assume external secrets management (e.g., Vault)
- **Apache-2.0 compatible** - all contributions must use permissive licensing
- **Audit-first mindset** - every sensitive action must log: Actor, Role, Tenant, Action, Resource, Timestamp, Outcome

## Policy Development

Policies use OPA Rego syntax in `policies/`:
- `deny_by_default.rego` - baseline deny-all policy
- `role_based_access.rego` - RBAC rules with tenant isolation
- `tests/role_access_test.rego` - policy unit tests

Example policy input structure:
```json
{
  "action": "read|write|delete|audit_read",
  "roles": ["agent-reader"],
  "tenant": "tenant-id",
  "resource_tenant": "resource-tenant-id",
  "resource": "path"
}
```

## Compliance Context

Changes should map to compliance controls where applicable:
- **SOC 2**: CC1/CC6 (access control), CC7 (monitoring), CC8 (change management)
- **ISO 27001**: A.5 (policies), A.9 (access), A.12 (operations), A.18 (compliance)

Detailed mappings are in `compliance/controls-mapping.md`.

## Recent Decisions - 2026-02-05

### Gateway: NGINX replaced with FastAPI middleware
- `gateway/middleware/main.py` is now the single-file gateway (220 lines)
- Replaced legacy `gateway/nginx.conf` (kept for reference, unused)
- FastAPI chosen for programmable request validation, rate limiting, and direct audit DB writes

### Gateway Request Flow (order is intentional)
1. `validate_request()` → 400 + audit `"invalid_request"`
2. `check_rate_limit()` → 429 + `Retry-After` header + audit `"rate_limited"`
3. `check_opa()` → 403 + audit `"deny"`
4. Proxy to Mem0 → audit `"allow"`
- Validation before rate limiting: malformed requests don't consume rate budget
- Rate limiting before OPA: protects policy engine from abuse

### Rate Limiting: in-memory sliding window
- `defaultdict(deque)` keyed by `tenant_id:actor_id`, no external dependencies
- Admin role gets `RATE_LIMIT_ADMIN_REQUESTS` (default 500); others get `RATE_LIMIT_REQUESTS` (default 100)
- Window size: `RATE_LIMIT_WINDOW_SECONDS` (default 60)
- For multi-worker/multi-instance production, replace with Redis-backed store

### Request Validation checks (in order)
1. Required headers: `X-User-Role` and `X-Tenant-Id` must be present
2. Path traversal: reject paths containing `..`
3. Content-Type: `application/json` required for POST/PUT/PATCH
4. Body size: must not exceed `MAX_BODY_SIZE_BYTES` (default 1MB)
5. JSON validity: body must parse as valid JSON

### Audit decision values
- `"allow"`, `"deny"`, `"invalid_request"`, `"rate_limited"`
- Column is `TEXT NOT NULL` — no schema migration needed for new values

### Route ordering matters
- `/health` must be defined BEFORE catch-all `/{path:path}` or FastAPI's catch-all intercepts it
- Bug was caught by tests and fixed

### Header contract
- `X-User-Id` (fallback `X-Forwarded-User`) → actor identity
- `X-User-Role` → RBAC role (required, rejected if missing)
- `X-Tenant-Id` → tenant context (required, rejected if missing)
- HTTP method mapping: GET→`read`, POST/PUT/PATCH→`write`, DELETE→`delete`

### Testing patterns
- **Unit tests** (`test_main.py`): 26 tests using pytest + `unittest.mock`
  - Mock `check_opa` and `log_audit` to isolate from OPA and PostgreSQL
  - Path traversal tested via direct `validate_request()` call (Starlette normalizes `../` before handler)
  - Rate limit state cleared between tests via `autouse` fixture
  - Run without Docker stack: `pytest test_main.py -v`

- **Integration tests** (`test_integration.py`): 25 tests against real services
  - Requires Docker stack running: `cd docker && docker compose up -d`
  - Tests Gateway (9000) → OPA (9001) → Audit DB (9005)
  - Validates full RBAC, rate limiting, audit logging, tenant isolation
  - Timestamp-based audit log cleanup between tests
  - Service health checks prevent false failures
  - Run with: `pytest test_integration.py -v`

- **Shared fixtures** (`conftest.py`): DB connection, cleanup, service checks, role headers
- **Total tests**: 3 OPA (rego) + 26 gateway unit + 25 gateway integration = 54 tests

### Naming conventions
- OPA: `{name}.rego`, tests `{name}_test.rego` in `policies/tests/`
- Python: `test_{module}.py` alongside source
- Docker: `gov_mem0_{service}` container names
- Keycloak: `realm-{name}.json`
- All Rego packages: `mem0.authz`
