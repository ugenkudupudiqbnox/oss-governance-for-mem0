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

### Service Ports (Local Development)
- Keycloak (IAM): http://localhost:9002 (admin/admin)
- OPA (Policy Engine): http://localhost:9001
- Grafana (Dashboards): http://localhost:9003
- Loki (Logs): http://localhost:9004

## Architecture

The project operates as a **sidecar/gateway pattern** around Mem0:

```
Client → NGINX Gateway → OPA Policy Check → Mem0
                ↓
         Audit Log (PostgreSQL)
                ↓
         Grafana/Loki (Observability)
```

**Key Layers:**
1. **IAM** (`iam/keycloak/`): Keycloak OIDC realm with RBAC roles
2. **Policy** (`policies/`): OPA Rego rules for authorization
3. **Audit** (`audit/`): PostgreSQL schema for immutable audit trails
4. **Gateway** (`gateway/`): NGINX config with auth_request to OPA
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
  "action": "read|write|audit_read",
  "roles": ["agent-reader"],
  "tenant": "tenant-id",
  "resource_tenant": "resource-tenant-id"
}
```

## Compliance Context

Changes should map to compliance controls where applicable:
- **SOC 2**: CC1/CC6 (access control), CC7 (monitoring), CC8 (change management)
- **ISO 27001**: A.5 (policies), A.9 (access), A.12 (operations), A.18 (compliance)

Detailed mappings are in `compliance/controls-mapping.md`.
