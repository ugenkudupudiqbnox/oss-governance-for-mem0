# Compliance Control Mapping

This document maps Governance Pack for Mem0 controls to common compliance frameworks.
It is intended as **guidance and evidence support**, not legal advice.

## SOC 2 Mapping (Selected)

### CC1 – Control Environment
- Defined roles: admin, agent-writer, agent-reader, auditor
- Separation of duties enforced via RBAC

### CC6 – Logical Access Controls
- Authentication via OIDC/OAuth2
- Least-privilege authorization via policy-as-code

### CC7 – System Operations
- Centralized logging
- Security event monitoring and alerting

### CC8 – Change Management
- Immutable audit logs for all write/delete operations

## ISO 27001 Mapping (Selected)

### A.5 – Information Security Policies
- Centralized, version-controlled policies

### A.9 – Access Control
- Role-based access
- Tenant isolation

### A.12 – Operations Security
- Logging and monitoring

### A.18 – Compliance
- Exportable audit logs for review
