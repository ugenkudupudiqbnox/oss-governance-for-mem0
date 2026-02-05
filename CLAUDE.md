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

---

## HIPAA Compliance TODOs

**Current Status:** Architecture supports HIPAA compliance, but NOT compliant out-of-box. The project is "HIPAA-ready" meaning core controls (audit logging, RBAC, policy enforcement) are implemented, but critical security features are missing.

**Implemented:**
- ✅ Audit Controls (45 CFR § 164.312(b)) - Immutable audit logs with actor/action/timestamp tracking
- ✅ Integrity Controls (45 CFR § 164.312(c)(1)) - Policy enforcement, deny-by-default
- ✅ Access Control - Unique User ID (45 CFR § 164.312(a)(1)) - Tracked in audit logs

**Critical Gaps (Required for HIPAA Compliance):**

### Phase 1: Critical Security (REQUIRED) 🔴

#### TODO-HIPAA-1: Enable TLS/HTTPS Encryption in Transit
**Priority:** CRITICAL
**Requirement:** 45 CFR § 164.312(e)(1) - Transmission Security
**Current:** Gateway runs HTTP only on port 9000
**Required:**
- Configure FastAPI with SSL/TLS certificates
- Update docker-compose.yml to mount certificates
- Force HTTPS redirects
- Disable HTTP endpoint in production
- Support TLS 1.2+ only

**Implementation:**
```yaml
# docker/docker-compose.yml
gateway:
  volumes:
    - ./certs:/certs:ro
  environment:
    SSL_CERT_FILE: /certs/server.crt
    SSL_KEY_FILE: /certs/server.key
```

---

#### TODO-HIPAA-2: Enable Encryption at Rest
**Priority:** CRITICAL
**Requirement:** 45 CFR § 164.312(a)(2)(iv) - Encryption and Decryption
**Current:** PostgreSQL stores audit logs and data in plain text
**Required:**
- Enable PostgreSQL Transparent Data Encryption (TDE) or pgcrypto
- Encrypt Docker volumes for persistent data
- Integrate with key management system (AWS KMS, HashiCorp Vault, Azure Key Vault)
- Document key rotation procedures

**Files to modify:**
- `docker/docker-compose.yml` - Add encrypted volume configuration
- `audit/init.sql` - Add pgcrypto extension if using column-level encryption

---

#### TODO-HIPAA-3: Implement Real Authentication
**Priority:** CRITICAL
**Requirement:** 45 CFR § 164.312(d) - Person or Entity Authentication
**Current:** Gateway trusts X-User-Id headers without verification
**Required:**
- Integrate gateway with Keycloak JWT token validation
- Remove trust of X-User-Id header - derive from verified JWT
- Add authentication middleware to FastAPI
- Validate token signature, expiration, issuer
- Support MFA through Keycloak

**Files to modify:**
- `gateway/middleware/main.py` - Add JWT validation middleware
- Add dependency: `python-jose[cryptography]` for JWT validation

---

#### TODO-HIPAA-4: Remove Hardcoded Secrets
**Priority:** CRITICAL
**Requirement:** General security best practice + 45 CFR § 164.308(a)(4) - Information Access Management
**Current:** docker-compose.yml contains plain text passwords
**Required:**
- Integrate with secrets management (Vault, AWS Secrets Manager, Azure Key Vault)
- Use Docker secrets or environment-based configuration
- Remove all hardcoded passwords from docker-compose.yml
- Implement credential rotation
- Document secrets management setup

**Files to modify:**
- `docker/docker-compose.yml` - Replace hardcoded passwords with secrets references
- Add secrets management documentation

---

### Phase 2: Additional Controls (IMPORTANT) 🟡

#### TODO-HIPAA-5: Implement Session Management
**Priority:** HIGH
**Requirement:** 45 CFR § 164.312(a)(2)(iii) - Automatic Logoff
**Current:** No session timeout enforcement
**Required:**
- Add session timeout configuration (default: 15 minutes idle, 8 hours absolute)
- Automatic logoff after inactivity period
- Session tracking in audit logs
- Force re-authentication after timeout
- Configurable timeout per role

---

#### TODO-HIPAA-6: Emergency Access Procedures
**Priority:** HIGH
**Requirement:** 45 CFR § 164.312(a)(2)(ii) - Emergency Access Procedure
**Current:** No break-glass mechanism
**Required:**
- Implement break-glass admin access
- Emergency access triggers additional audit logging
- Temporary elevated permissions with time limit
- Require justification for emergency access (logged)
- Post-access review workflow

---

#### TODO-HIPAA-7: PHI Classification and Handling
**Priority:** MEDIUM
**Requirement:** 45 CFR § 164.502(b) - Minimum Necessary
**Current:** No distinction between PHI and non-PHI data
**Required:**
- Add PHI classification metadata to memory objects
- Enhanced audit logging for PHI access
- Additional access controls for PHI
- Support for de-identification of PHI
- Document PHI handling procedures

---

#### TODO-HIPAA-8: Access Control - Context-Based Access
**Priority:** MEDIUM
**Current:** Only role-based access control
**Required:**
- Add attribute-based access control (ABAC) support in OPA
- Consider: time-based access, location-based access, device-based access
- Document context evaluation in policies

---

### Phase 3: Documentation & Procedures (COMPLIANCE) 📋

#### TODO-HIPAA-9: Contingency Planning
**Priority:** MEDIUM
**Requirement:** 45 CFR § 164.308(a)(7) - Contingency Plan
**Current:** No formal contingency plan
**Required:**
- Document backup and recovery procedures
- Create disaster recovery plan (RTO/RPO targets)
- Document business continuity procedures
- Create backup verification procedures
- Test disaster recovery annually

**Create:** `compliance/contingency_plan.md`

---

#### TODO-HIPAA-10: Formal Risk Assessment
**Priority:** MEDIUM
**Requirement:** 45 CFR § 164.308(a)(1)(ii)(A) - Risk Assessment
**Current:** Threat model exists but not formal HIPAA risk assessment
**Required:**
- Conduct formal HIPAA risk analysis
- Document identified risks and mitigations
- Create risk register
- Update annually or when significant changes occur

**Create:** `compliance/risk_assessment.md`

---

#### TODO-HIPAA-11: Security Policies and Procedures
**Priority:** MEDIUM
**Requirement:** 45 CFR § 164.308(a)(1) - Security Management Process
**Current:** Technical controls documented, administrative policies incomplete
**Required:**
- Written security policies document
- Access control procedures
- Password policies (if using local auth)
- Incident response procedures (expand current playbook)
- Workforce security policies
- Information access management policies

**Create:** `compliance/security_policies.md`

---

#### TODO-HIPAA-12: Business Associate Agreement (BAA) Template
**Priority:** LOW
**Requirement:** 45 CFR § 164.504(e) - Business Associate Contracts
**Current:** Not provided
**Required:**
- Create template BAA for organizations deploying this pack
- Document BAA requirements for cloud providers
- List of required BAA terms

**Create:** `compliance/baa_template.md`

---

### Testing & Validation

#### TODO-HIPAA-13: Security Testing
**Required:**
- Penetration testing against hardened deployment
- Vulnerability scanning (OWASP Top 10, CWE Top 25)
- Third-party security audit
- Compliance attestation from qualified auditor

---

#### TODO-HIPAA-14: Compliance Testing
**Required:**
- Create HIPAA compliance test suite
- Automated checks for encryption, authentication, audit logging
- Regular compliance validation
- Document test results for audit evidence

**Create:** `tests/compliance/test_hipaa_requirements.py`

---

## HIPAA Compliance Summary

**Current State:** ~40% HIPAA compliant
- ✅ Audit logging (100%)
- ✅ Access control framework (80% - missing authentication, session mgmt)
- ❌ Encryption (0% - neither in-transit nor at-rest)
- ⚠️ Administrative safeguards (30% - some docs, missing procedures)

**Estimated Work:** 6-8 weeks for full HIPAA compliance (Phases 1-3 + testing)

**Deployment Options:**
1. **Deploy behind existing HIPAA-compliant infrastructure** - Leverage cloud provider's HIPAA compliance for encryption, network security (compensating controls)
2. **Full independent compliance** - Complete all TODOs above
3. **Hybrid approach** - Critical features (Phase 1) + cloud provider for infrastructure

**Important:** This is technical assessment only. HIPAA compliance requires:
- Legal review by qualified attorney
- Business Associate Agreements
- Formal policies and procedures
- Workforce training
- Third-party audit/attestation
