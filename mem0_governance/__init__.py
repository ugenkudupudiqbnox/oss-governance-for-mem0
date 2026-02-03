"""
Mem0 Governance Pack

An open-source governance, security, audit, and compliance layer for Mem0 (OSS).
This is a companion layer only - it does not modify Mem0 or imply any affiliation.

Key Features:
- RBAC (Role-Based Access Control)
- Multi-tenant isolation
- Deny-by-default policies
- Immutable audit logs
- No hard-coded secrets
- Apache-2.0 compatible

Copyright 2024 - Licensed under Apache-2.0
"""

__version__ = "0.1.0"

from mem0_governance.rbac import Role, Permission, RBACManager
from mem0_governance.tenant import TenantContext, TenantManager, TenantStatus
from mem0_governance.policy import Policy, PolicyEngine, PolicyDecision
from mem0_governance.audit import AuditLogger, AuditEvent, AuditEventType, AuditSeverity
from mem0_governance.security import SecretManager, InputValidator

__all__ = [
    "Role",
    "Permission",
    "RBACManager",
    "TenantContext",
    "TenantManager",
    "TenantStatus",
    "Policy",
    "PolicyEngine",
    "PolicyDecision",
    "AuditLogger",
    "AuditEvent",
    "AuditEventType",
    "AuditSeverity",
    "SecretManager",
    "InputValidator",
]
