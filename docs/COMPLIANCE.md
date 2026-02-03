# Compliance Guide

This guide explains how the Mem0 Governance Pack helps organizations meet regulatory and compliance requirements.

## Regulatory Frameworks Supported

The governance pack provides controls that support compliance with:

- **SOC 2** (Service Organization Control 2)
- **GDPR** (General Data Protection Regulation)
- **HIPAA** (Health Insurance Portability and Accountability Act)
- **ISO 27001** (Information Security Management)
- **PCI DSS** (Payment Card Industry Data Security Standard)
- **FedRAMP** (Federal Risk and Authorization Management Program)

## Core Compliance Features

### 1. Access Control (RBAC)

**Compliance Requirements Met:**
- SOC 2: CC6.1 - Logical and physical access controls
- ISO 27001: A.9 Access Control
- HIPAA: 164.308(a)(3) - Workforce access management

**Implementation:**
```python
from mem0_governance import RBACManager, Role, Permission

rbac = RBACManager()

# Create user with specific role
user = rbac.create_subject(
    subject_id="user123",
    name="John Doe",
    roles={Role.USER},  # Least privilege
    tenant_id="tenant1"
)

# Check permission before access
if rbac.check_permission("user123", Permission.MEMORY_READ, "tenant1"):
    # Grant access
    pass
```

**Audit Evidence:**
- Role assignments logged to audit trail
- Permission checks logged with outcomes
- Access denied events logged for investigation

### 2. Audit Logging

**Compliance Requirements Met:**
- SOC 2: CC7.2 - System monitoring
- GDPR: Article 30 - Records of processing activities
- HIPAA: 164.312(b) - Audit controls
- PCI DSS: Requirement 10 - Track and monitor all access

**Implementation:**
```python
from mem0_governance import AuditLogger, AuditEventType

audit_logger = AuditLogger()

# Log all sensitive operations
audit_logger.log_event(
    event_type=AuditEventType.MEMORY_READ,
    actor_id="user123",
    actor_name="John Doe",
    action="read_memory",
    result="success",
    tenant_id="tenant1",
    resource_type="memory",
    resource_id="mem456",
    source_ip="192.168.1.100",
)
```

**Audit Log Properties:**
- Immutable (append-only)
- Cryptographically chained (tamper detection)
- Comprehensive event coverage
- Exportable for compliance reporting
- Configurable retention (default: 365 days)

### 3. Data Segregation (Multi-Tenancy)

**Compliance Requirements Met:**
- SOC 2: CC6.6 - Logical access controls
- ISO 27001: A.13.1 Network security management
- GDPR: Article 32 - Security of processing
- FedRAMP: AC-4 - Information flow enforcement

**Implementation:**
```python
from mem0_governance import TenantManager

tenant_mgr = TenantManager()

# Create isolated tenant
tenant = tenant_mgr.create_tenant(
    tenant_id="healthcare-org",
    name="Healthcare Organization",
)

# Enforce tenant isolation
can_access = tenant_mgr.validate_tenant_access(
    tenant_id="healthcare-org",
    resource_tenant_id="finance-org"  # Returns False
)
```

**Isolation Properties:**
- Strict tenant separation
- No cross-tenant data access
- Tenant-scoped operations
- Resource limits per tenant

### 4. Policy Enforcement

**Compliance Requirements Met:**
- SOC 2: CC6.2 - Authorization
- ISO 27001: A.9.4 System and application access control
- FedRAMP: AC-3 - Access enforcement

**Implementation:**
```python
from mem0_governance import PolicyEngine

policy_engine = PolicyEngine()

# Load policies from files
policy_engine.load_policies_from_directory("./policies")

# Evaluate access
decision = policy_engine.evaluate(
    action="memory:delete",
    resource="memory:tenant:healthcare:sensitive-data",
    context={"tenant_id": "healthcare", "data_classification": "PHI"}
)
```

**Policy Properties:**
- Deny-by-default
- Policy-as-code (version controlled)
- Explicit allow rules required
- Condition-based access

### 5. Security Controls

**Compliance Requirements Met:**
- SOC 2: CC7.1 - Detection of security events
- GDPR: Article 32 - Security measures
- HIPAA: 164.312(a)(1) - Technical safeguards
- PCI DSS: Requirement 6 - Secure systems

**Implementation:**
```python
from mem0_governance.security import (
    SecretManager,
    InputValidator,
    RateLimiter
)

# No hard-coded secrets
secret_mgr = SecretManager()
api_key = secret_mgr.get_secret("API_KEY")

# Input validation
validator = InputValidator()
if validator.validate_safe_input(user_input):
    # Process input
    pass

# Rate limiting
rate_limiter = RateLimiter(max_requests=100, window_seconds=60)
if rate_limiter.check_rate_limit(user_id):
    # Allow request
    pass
```

**Security Features:**
- No secrets in source code
- Input validation and sanitization
- SQL injection prevention
- XSS prevention
- Rate limiting

## Compliance Documentation

### Audit Trail Export

For compliance reporting, export audit logs:

```python
# Export for compliance review
logs_json = audit_logger.export_events(
    format="json",
    tenant_id="healthcare-org",
    start_time=datetime(2024, 1, 1),
    end_time=datetime(2024, 12, 31),
)

# Save for auditor review
with open("compliance_audit_2024.json", "w") as f:
    f.write(logs_json)
```

### Integrity Verification

Verify audit log integrity for compliance:

```python
# Verify no tampering
is_valid = audit_logger.verify_integrity()
if not is_valid:
    # Alert compliance team
    raise SecurityError("Audit log integrity compromised")
```

### Access Control Reports

Generate access control reports:

```python
# List users and their permissions
tenant_users = rbac.list_subjects_by_tenant("healthcare-org")

for user in tenant_users:
    permissions = user.get_all_permissions()
    print(f"User: {user.name}, Roles: {user.roles}, Permissions: {permissions}")
```

## Compliance Checklist

### SOC 2 Type II

- [x] Logical access controls (RBAC)
- [x] System monitoring and logging
- [x] Security incident management (audit logs)
- [x] Change management (policy-as-code)
- [x] Risk assessment framework (deny-by-default)

### GDPR

- [x] Data protection by design (tenant isolation)
- [x] Records of processing (audit logs)
- [x] Security of processing (encryption, validation)
- [x] Data breach detection (audit monitoring)
- [x] Access control measures (RBAC, policies)

### HIPAA

- [x] Access control (164.312(a)(1))
- [x] Audit controls (164.312(b))
- [x] Integrity controls (hash chaining)
- [x] Transmission security (secure configs)
- [x] Unique user identification (subject IDs)

### ISO 27001

- [x] A.9 Access Control
- [x] A.12 Operations Security
- [x] A.13 Network Security
- [x] A.14 System Acquisition
- [x] A.18 Compliance

### PCI DSS

- [x] Requirement 2: Secure configurations
- [x] Requirement 6: Secure systems
- [x] Requirement 7: Restrict access
- [x] Requirement 8: Unique IDs
- [x] Requirement 10: Track and monitor

## Audit Preparation

### For External Audits

1. **Prepare Audit Logs**
   ```python
   # Export full audit trail
   full_audit = audit_logger.export_events(format="json")
   ```

2. **Verify Integrity**
   ```python
   # Prove no tampering
   assert audit_logger.verify_integrity()
   ```

3. **Document Access Controls**
   - List all roles and permissions
   - Document policy definitions
   - Provide tenant isolation evidence

4. **Security Controls Evidence**
   - Secret management configuration
   - Input validation implementation
   - Rate limiting configuration

### Retention Policies

Configure retention per regulatory requirements:

```python
from mem0_governance.config import GovernanceConfig

config = GovernanceConfig(
    audit_retention_days=365,  # HIPAA: 6 years recommended
    audit_export_enabled=True,
)
```

**Recommended Retention:**
- SOC 2: 12 months minimum
- GDPR: As long as processing occurs
- HIPAA: 6 years
- PCI DSS: 12 months minimum
- ISO 27001: Per organization policy

## Continuous Compliance

### Monitoring

Set up continuous monitoring:

```python
# Monitor critical security events
critical_events = audit_logger.get_events(
    severity=AuditSeverity.CRITICAL,
)

for event in critical_events:
    # Alert security team
    send_alert(event)
```

### Regular Reviews

Schedule regular compliance reviews:

1. **Quarterly**: Review access controls and permissions
2. **Monthly**: Review audit logs for anomalies
3. **Weekly**: Verify audit log integrity
4. **Daily**: Monitor critical security events

### Policy Updates

Maintain policy version control:

```yaml
# policies/version-controlled-policy.yaml
id: "data-access-policy"
name: "Data Access Policy"
version: "2.1"  # Increment on changes
description: "Updated to meet new compliance requirements"
```

## Compliance References

### SOC 2 Trust Service Criteria
- CC6: Logical and Physical Access Controls
- CC7: System Operations
- CC8: Change Management

### GDPR Articles
- Article 5: Principles relating to processing
- Article 25: Data protection by design
- Article 30: Records of processing activities
- Article 32: Security of processing

### HIPAA Security Rule
- 164.308: Administrative Safeguards
- 164.310: Physical Safeguards
- 164.312: Technical Safeguards
- 164.316: Policies and Procedures

### ISO 27001 Annex A
- A.9: Access Control
- A.12: Operations Security
- A.18: Compliance

## Contact

For compliance questions or audit requests, please contact: compliance@[your-domain]
