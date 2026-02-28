# Governance Pack for Mem0: Architecture Guide

This guide provides a detailed overview of the architecture, integration points, and design patterns for developers and integrators deploying the Governance Pack for Mem0 in enterprise and regulated environments.

## Overview
The Governance Pack operates as a sidecar/gateway layer around Mem0, enforcing security, audit, and compliance controls without modifying Mem0 itself.

### High-Level Architecture
```
Client → FastAPI Gateway (9000) → OPA Policy Engine (9001) → Mem0 Backend (9006)
                ↓
         Audit Log (PostgreSQL 9005)
                ↓
         Grafana/Loki (9003/9004)
```

- **Gateway:** FastAPI proxy with request validation, rate limiting, OPA policy checks, and audit logging.
- **OPA:** Open Policy Agent for declarative authorization (Rego policies).
- **Audit DB:** PostgreSQL for immutable, append-only audit logs.
- **IAM:** Keycloak for RBAC, OIDC authentication, and multi-tenant isolation.
- **Observability:** Grafana dashboards for audit log visualization; Loki for log aggregation.

## Key Components

### 1. API Gateway (gateway/middleware/main.py)
- **Request Validation:** Enforces required headers, path traversal protection, content-type, body size, and JSON validity.
- **Rate Limiting:** Sliding window per tenant/actor; configurable via environment variables.
- **OPA Integration:** Calls OPA for policy decisions before proxying to Mem0.
- **Audit Logging:** Every sensitive action is logged with actor, role, tenant, action, resource, timestamp, and outcome.
- **RBAC Enforcement:** Explicit roles (`admin`, `agent-writer`, `agent-reader`, `auditor`) enforced via Keycloak and OPA.

### 2. Policy Engine (policies/)
- **Rego Policies:** Declarative rules for deny-by-default, RBAC, and tenant isolation.
- **Policy Tests:** Unit tests in policies/tests/ validate policy logic.
- **Integration:** Gateway queries OPA at /v1/data/mem0/authz/allow for each request.

### 3. Audit Logging (audit/)
- **Schema:** PostgreSQL schema for mem0_audit_log table; append-only, tamper-evident.
- **Seeding:** audit_log_seed.sql for sample/test data.
- **Export:** Logs can be exported via SQL or Grafana UI for compliance evidence.

### 4. IAM & RBAC (iam/keycloak/)
- **Keycloak Realm:** Predefined roles and clients for secure authentication and authorization.
- **OIDC Integration:** Gateway validates JWT tokens and enforces role-based access.
- **Multi-Tenancy:** Tenant context enforced in headers and audit logs.

### 5. Observability (observability/grafana/)
- **Dashboards:** Auditor dashboard auto-provisioned for compliance review.
- **Loki:** Optional log aggregation for advanced monitoring.

## Deployment Patterns
- **Sidecar/Gateway:** Governance controls are enforced externally; Mem0 is treated as a black box.
- **Multi-Tenant:** All components support strong tenant isolation.
- **Least Privilege:** Deny-by-default and explicit allow rules for all access.
- **Audit-First:** Every sensitive action is logged for compliance.

## Integration Points
- **Mem0 Backend:** No code changes required; all governance logic is external.
- **External IAM:** Integrate with existing OIDC providers if needed.
- **Custom Dashboards:** Add new Grafana dashboards by placing JSON files in docker/dashboards/.
- **Secrets Management:** Use environment variables or Docker secrets; never hard-code secrets.

## Extending the Pack
- **Add Policies:** Create new .rego files in policies/ and test in policies/tests/.
- **Add Audit Fields:** Update audit/audit_log_schema.sql and gateway/middleware/main.py.
- **Add Roles:** Update Keycloak realm and OPA policies.
- **Add Dashboards:** Place dashboard JSON in docker/dashboards/ for auto-provisioning.

## Compliance Mapping
- See compliance/controls-mapping.md for SOC 2, ISO 27001, HIPAA mappings.
- Use docs/QUICKSTART_AUDITOR.md for evidence export and dashboard usage.

## Best Practices
- **Do not modify Mem0 source code.**
- **Use declarative policies and explicit RBAC.**
- **Log every sensitive action.**
- **Document all controls and mappings for auditability.**

---

For further details, see README.md, docs/QUICKSTART_AUDITOR.md, and compliance/controls-mapping.md.
