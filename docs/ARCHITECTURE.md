# Architecture Overview

## System Design

The Mem0 Governance Pack is designed as a modular, layered architecture that provides security, audit, and compliance controls without modifying Mem0 itself.

```
┌─────────────────────────────────────────────────────┐
│              Application Layer (Your App)            │
└────────────────┬────────────────────────────────────┘
                 │
┌────────────────▼────────────────────────────────────┐
│           Mem0 Governance Pack                      │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐           │
│  │   RBAC   │ │  Tenant  │ │  Policy  │           │
│  │ Manager  │ │ Manager  │ │  Engine  │           │
│  └──────────┘ └──────────┘ └──────────┘           │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐           │
│  │  Audit   │ │ Security │ │  Config  │           │
│  │  Logger  │ │ Manager  │ │ Manager  │           │
│  └──────────┘ └──────────┘ └──────────┘           │
└────────────────┬────────────────────────────────────┘
                 │
┌────────────────▼────────────────────────────────────┐
│                 Mem0 (OSS)                          │
└─────────────────────────────────────────────────────┘
```

## Core Components

### 1. RBAC Manager
**Purpose**: Role-Based Access Control with deny-by-default semantics

**Key Classes**:
- `Role`: Enum of predefined roles (Admin, Auditor, User, ReadOnly, Guest)
- `Permission`: Fine-grained permissions for operations
- `Subject`: Entity with roles and permissions
- `RBACManager`: Central RBAC enforcement

**Flow**:
1. Create subject with roles
2. Check permission before operation
3. Deny access if permission not granted
4. Log all permission checks to audit log

### 2. Tenant Manager
**Purpose**: Multi-tenant isolation and context management

**Key Classes**:
- `TenantContext`: Represents a tenant with metadata and limits
- `TenantManager`: Manages tenant lifecycle and isolation

**Flow**:
1. Create tenant with unique ID
2. Set current tenant context for request
3. Validate all operations are within tenant scope
4. Deny cross-tenant access

### 3. Policy Engine
**Purpose**: Deny-by-default policy evaluation with policy-as-code

**Key Classes**:
- `Policy`: Collection of policy statements
- `PolicyStatement`: Single allow/deny rule
- `PolicyEngine`: Evaluates policies for actions

**Evaluation Rules**:
1. If no policies match → DENY
2. If any explicit DENY matches → DENY
3. If any ALLOW matches and no DENY → ALLOW
4. Otherwise → DENY

**Policy Format** (YAML):
```yaml
id: "policy-id"
name: "Policy Name"
statements:
  - effect: "allow"
    actions: ["memory:read"]
    resources: ["memory:tenant:*:*"]
    conditions:
      tenant_id:
        equals: "tenant-123"
```

### 4. Audit Logger
**Purpose**: Immutable audit trail with cryptographic integrity

**Key Classes**:
- `AuditEvent`: Immutable event record
- `AuditLogger`: Append-only logger with hash chaining

**Features**:
- Hash chaining: Each event includes hash of previous event
- Tamper detection: `verify_integrity()` detects modifications
- Export: JSON/CSV export for compliance
- Filtering: Query by tenant, actor, event type, time range

**Hash Chain**:
```
Event 1 → hash1
Event 2 → hash2 (includes hash1)
Event 3 → hash3 (includes hash2)
...
```

### 5. Security Manager
**Purpose**: Secret management and input validation

**Key Classes**:
- `SecretManager`: Environment-based secret management
- `InputValidator`: SQL injection, XSS, format validation
- `RateLimiter`: Request throttling

**No Hard-Coded Secrets**:
```python
# ✅ Correct - from environment
secret_mgr = SecretManager()
api_key = secret_mgr.get_secret("API_KEY")

# ❌ Wrong - hard-coded
api_key = "sk-1234567890"  # NEVER DO THIS
```

### 6. Config Manager
**Purpose**: Configuration without secrets

**Key Classes**:
- `GovernanceConfig`: Central configuration

**Configuration Sources**:
1. Environment variables (for secrets and overrides)
2. Config files (for non-sensitive settings)
3. Defaults (fail-safe values)

## Security Principles

### 1. Deny-by-Default
Everything is denied unless explicitly allowed.

### 2. Tenant Isolation
Strict separation between tenants. No cross-tenant data access.

### 3. Immutable Audit Logs
Audit events cannot be modified or deleted. Tampering is detectable.

### 4. No Secrets in Code
All secrets come from environment variables or secure vaults.

### 5. Defense in Depth
Multiple layers of security: RBAC, policies, tenant isolation, input validation.

## Integration Pattern

### Wrapping Mem0 Operations

```python
from mem0_governance import (
    RBACManager, Permission,
    TenantManager,
    PolicyEngine,
    AuditLogger, AuditEventType,
)

# Initialize
rbac = RBACManager()
tenant_mgr = TenantManager()
policy_engine = PolicyEngine()
audit_logger = AuditLogger()

def secure_memory_read(user_id, tenant_id, memory_id):
    """Secure wrapper around Mem0 memory read"""
    
    # 1. Set tenant context
    if not tenant_mgr.set_current_tenant(tenant_id):
        raise ValueError("Invalid tenant")
    
    # 2. Check RBAC permission
    if not rbac.check_permission(user_id, Permission.MEMORY_READ, tenant_id):
        audit_logger.log_event(
            event_type=AuditEventType.SECURITY_ACCESS_DENIED,
            actor_id=user_id,
            actor_name=get_user_name(user_id),
            action="read_memory",
            result="denied",
            tenant_id=tenant_id,
            resource_id=memory_id,
        )
        raise PermissionError("Access denied")
    
    # 3. Evaluate policies
    decision = policy_engine.evaluate(
        action="memory:read",
        resource=f"memory:tenant:{tenant_id}:{memory_id}",
        context={"tenant_id": tenant_id, "user_id": user_id},
    )
    
    if decision == PolicyDecision.DENIED:
        audit_logger.log_event(
            event_type=AuditEventType.POLICY_EVALUATE,
            actor_id=user_id,
            actor_name=get_user_name(user_id),
            action="policy_deny",
            result="denied",
            tenant_id=tenant_id,
        )
        raise PermissionError("Policy denied access")
    
    # 4. Perform operation (call Mem0)
    try:
        result = mem0_client.get(memory_id)
        
        # 5. Log success
        audit_logger.log_event(
            event_type=AuditEventType.MEMORY_READ,
            actor_id=user_id,
            actor_name=get_user_name(user_id),
            action="read_memory",
            result="success",
            tenant_id=tenant_id,
            resource_type="memory",
            resource_id=memory_id,
        )
        
        return result
        
    except Exception as e:
        # Log failure
        audit_logger.log_event(
            event_type=AuditEventType.MEMORY_READ,
            actor_id=user_id,
            actor_name=get_user_name(user_id),
            action="read_memory",
            result="error",
            tenant_id=tenant_id,
            resource_id=memory_id,
            details={"error": str(e)},
        )
        raise
```

## Deployment Considerations

### Production Requirements
1. Store secrets in environment variables or vault (AWS Secrets Manager, HashiCorp Vault, etc.)
2. Use TLS/SSL for all network communication
3. Enable audit log persistence to secure storage
4. Regular security audits and penetration testing
5. Monitor audit logs for suspicious activity

### Scaling
- All managers are stateless (can be replicated)
- Audit logs should be stored in a centralized system
- Consider distributed policy engine for high throughput
- Use caching for frequently accessed policies

### Compliance
- Retain audit logs per regulatory requirements (default: 365 days)
- Implement log rotation and archival
- Provide audit log export for compliance reporting
- Regular integrity verification of audit logs
