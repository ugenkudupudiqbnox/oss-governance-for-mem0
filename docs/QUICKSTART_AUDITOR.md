# Quick Start Guide: Auditors & Compliance Teams

This guide helps auditors and compliance professionals use the Governance Pack for Mem0 to review, validate, and export evidence for SOC 2, ISO 27001, HIPAA, and other frameworks.

## Prerequisites
- Governance stack running (`cd docker && docker compose up -d`)
- Auditor role assigned in Keycloak (`X-User-Role: auditor`)
- Access to audit endpoints via the gateway

## Typical Auditor Tasks
- Review audit logs for sensitive actions (read, write, delete)
- Validate RBAC enforcement and tenant isolation
- Export evidence for compliance reports
- Check policy configuration and enforcement

## Example: Retrieve Audit Logs

```http
GET http://localhost:9000/audit
Headers:
  X-User-Id: auditor001
  X-User-Role: auditor
  X-Tenant-Id: tenantA
```

## What You Can See
- All actions performed by agents, admins, and other users in your tenant
- Actor, role, tenant, action, resource, timestamp, outcome
- Only allowed to view audit logs (not memory/ticket data)

## Exporting Evidence
- Use SQL queries against the audit DB (PostgreSQL) to export logs:

```bash
docker exec gov_mem0_audit_db psql -U audit -d audit -c \
  "SELECT * FROM mem0_audit_log WHERE tenant_id = 'tenantA' ORDER BY timestamp DESC LIMIT 100;"
```
- Export results to CSV for compliance documentation

## Validating RBAC & Policy Enforcement
- Confirm denied actions (e.g., agent-reader denied write) are logged
- Check for tenant isolation (no cross-tenant access)
- Review policy files in `policies/` for explicit allow/deny rules

## Troubleshooting
- **403 Forbidden:** Only auditor role can access audit endpoints
- **Missing logs:** Check gateway and audit DB health
- **Policy changes:** Review `policies/role_based_access.rego` and test with `opa test policies/ -v`

## References
- [CLAUDE.md](../CLAUDE.md) – Architecture, audit, compliance mappings
- [audit/audit_log_schema.sql](../audit/audit_log_schema.sql) – Audit log schema
- [policies/role_based_access.rego](../policies/role_based_access.rego) – RBAC rules
- [gateway/middleware/main.py](../gateway/middleware/main.py) – Audit logging logic

---

**Tip:**
All sensitive actions are logged and exportable. Use the platform’s audit features to produce defensible evidence for compliance reviews.
