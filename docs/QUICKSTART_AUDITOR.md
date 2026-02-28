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

### Simple Web UI Method (Recommended)
You can download and review audit logs directly in Grafana without technical steps:

1. Open Grafana at [http://localhost:9003](http://localhost:9003)
2. Log in with your auditor credentials
3. Go to the **Auditor Dashboard**
4. Use filters (tenant, actor, action, date) to find the logs you need
5. Click the **panel title** (e.g., "Audit Events") → **Inspect** → **Download CSV**
6. Save the CSV file for your compliance report

This method requires no command line or SQL knowledge. All evidence can be reviewed and exported from the web interface.

### Advanced SQL Method (Optional)
If you need more control, you can use SQL queries against the audit DB (PostgreSQL):
```bash
docker exec gov_mem0_audit_db psql -U audit -d audit -c \
  "SELECT * FROM mem0_audit_log WHERE tenant_id = 'tenantA' ORDER BY timestamp DESC LIMIT 100;"
```
Export results to CSV for compliance documentation.

## Validating RBAC & Policy Enforcement
- Confirm denied actions (e.g., agent-reader denied write) are logged
- Check for tenant isolation (no cross-tenant access)
- Review policy files in `policies/` for explicit allow/deny rules

## Troubleshooting
- **403 Forbidden:** Only auditor role can access audit endpoints
- **Missing logs:** Check gateway and audit DB health
- **Policy changes:** Review `policies/role_based_access.rego` and test with `opa test policies/ -v`

## Enabling Grafana Auditor Dashboards
## Automatic Dashboard Provisioning

Auditor dashboards are now auto-loaded when Grafana starts:

- Dashboards in `docker/dashboards/` are provisioned via `docker/grafana-provisioning-dashboards.yaml`
- No manual import required—dashboards appear in Grafana on first login
- To add new dashboards, place JSON files in `docker/dashboards/` and restart Grafana

This ensures compliance dashboards are always available for auditors and compliance teams.
## Compliance Checklist: SOC 2, ISO 27001, HIPAA
## Audit Dashboard Field Mapping to Compliance Controls

The table below shows how dashboard fields map to common compliance requirements. Use this as a reference when preparing evidence for SOC 2, ISO 27001, or HIPAA:

| Dashboard Field | SOC 2 | ISO 27001 | HIPAA |
|-----------------|-------|-----------|-------|
| Actor           | CC6   | A.9       | 164.312(a)(1) |
| Role            | CC6   | A.9       | 164.312(a)(1) |
| Tenant          | CC6   | A.9       | 164.312(a)(1) |
| Action          | CC7   | A.12      | 164.312(b)    |
| Resource        | CC7   | A.12      | 164.312(b)    |
| Timestamp       | CC7   | A.12      | 164.312(b)    |
| Outcome         | CC8   | A.18      | 164.312(c)(1) |

**How to use:**
- When exporting logs, reference this table to show how each field supports compliance evidence.
- For audits, include this mapping in your report to simplify control validation.

For more details, see [compliance/controls-mapping.md](../compliance/controls-mapping.md).

To meet audit and evidence requirements for SOC 2, ISO 27001, and HIPAA, ensure the following in Grafana and documentation:

### 1. Audit Log Visualization
- Dashboards must display: actor, role, tenant, action, resource, timestamp, outcome
- Use filters to support evidence queries by tenant, user, or action

### 2. Evidence Export
- Document how to export audit logs (CSV/JSON) from Grafana for compliance reviews
- Example: Use dashboard export or SQL query (see Exporting Evidence above)

### 3. Access Controls
- Restrict dashboard access to authorized auditor roles (enforced via Keycloak RBAC)
- Document RBAC enforcement and access review procedures

### 4. Retention & Integrity
- Document audit log retention policy and tamper-evidence controls (see compliance/data_retention_deletion.md)
- Note: Grafana does not modify logs; integrity is enforced at the DB/gateway layer

### 5. Dashboard Documentation
- Link dashboard JSON and usage instructions in compliance evidence (this guide, controls-mapping.md)
- Reference audit dashboard in compliance/controls-mapping.md for control mapping

---

Grafana provides real-time visualization of audit logs for compliance review.

### 1. Start Grafana
Ensure the governance stack is running:
```bash
cd docker && docker compose up -d
```
Grafana will be available at [http://localhost:9003](http://localhost:9003).

### 2. Log In
Default admin credentials (change in production):
- **Username:** admin
- **Password:** admin

### 3. Add PostgreSQL Data Source
1. Go to **Configuration → Data Sources**
2. Click **Add data source** → Select **PostgreSQL**
3. Set these values:
  - **Host:** `audit-db:5432`
  - **Database:** `audit`
  - **User:** `audit`
  - **Password:** `audit`
  - **SSL Mode:** `disable` (for local/dev)
4. Click **Save & Test** (should show "Database Connection OK")

### 4. Import Auditor Dashboard
1. Go to **Dashboards → Import**
2. Upload or paste the JSON from `observability/grafana/audit_dashboard.json`
3. Select the PostgreSQL data source you configured above
4. Click **Import**

### 5. View Audit Events
The dashboard will show audit log events filtered by tenant, actor, action, and outcome. Use filters to export evidence for compliance.

## References
- [audit/audit_log_schema.sql](../audit/audit_log_schema.sql) – Audit log schema
- [policies/role_based_access.rego](../policies/role_based_access.rego) – RBAC rules
- [gateway/middleware/main.py](../gateway/middleware/main.py) – Audit logging logic

---

**Tip:**
All sensitive actions are logged and exportable. Use the platform’s audit features to produce defensible evidence for compliance reviews.
