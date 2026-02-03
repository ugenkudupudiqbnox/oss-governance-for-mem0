# Data Retention & Deletion Policy

This document defines reference data retention and deletion practices for
Governance Pack for Mem0. It is intended to support compliance requirements and
organizational policy alignment.

## Scope
- Agent memory metadata
- Audit logs
- Authorization and access records

## Retention Policy

### Agent Memory
- Retention period defined by application owner
- Policies should enforce minimum data retention
- Access remains governed by RBAC and tenant isolation

### Audit Logs
- Retained for a minimum of 1–7 years (based on compliance requirements)
- Stored in append-only, tamper-evident storage
- Not modifiable or deletable by standard users

## Deletion Policy

### Memory Deletion
- Memory deletion must be an explicit, authorized action
- All deletions are logged with actor, role, tenant, and timestamp

### Right to Erasure (GDPR / DPDP)
- Supports downstream data subject requests
- Deletion events remain auditable

### Audit Log Deletion
- Audit logs are exempt from routine deletion
- Deletion only permitted under legal approval

## Review & Governance
- Policies reviewed periodically
- Changes tracked via version control
