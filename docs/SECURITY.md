# Security Guidelines

## Security Best Practices

This document outlines security best practices when using the Mem0 Governance Pack.

## 1. Secret Management

### ✅ DO: Use Environment Variables
```python
from mem0_governance.security import SecretManager

secret_mgr = SecretManager(prefix="MEM0_GOV_")
api_key = secret_mgr.get_secret("API_KEY")
db_password = secret_mgr.get_secret("DB_PASSWORD")
```

Set secrets in environment:
```bash
export MEM0_GOV_API_KEY="your-secret-key-here"
export MEM0_GOV_DB_PASSWORD="your-db-password"
```

### ❌ DON'T: Hard-Code Secrets
```python
# NEVER DO THIS
api_key = "sk-1234567890abcdef"  # ❌ Security violation
db_password = "password123"        # ❌ Security violation
```

### Secret Strength Requirements
- Minimum 32 characters (configurable)
- At least 3 character types (upper, lower, digit, special)
- No common patterns or dictionary words
- Rotate secrets regularly (90 days recommended)

```python
# Validate secret strength
from mem0_governance.security import SecretManager

secret_mgr = SecretManager()
is_strong = secret_mgr.validate_secret_strength(
    secret="MyStr0ng!Secret#2024$XyZ123",
    min_length=32
)
```

## 2. Input Validation

### Validate All User Inputs
```python
from mem0_governance.security import InputValidator

validator = InputValidator()

# Validate alphanumeric
if validator.validate_alphanumeric(user_id, allow_extended=True):
    # Safe to use
    pass

# Validate email
if validator.validate_email(email):
    # Safe to use
    pass

# Check for SQL injection
if validator.check_sql_injection(query):
    raise ValueError("SQL injection detected")

# Check for XSS
if validator.check_xss(html_content):
    raise ValueError("XSS pattern detected")

# Comprehensive safety check
if validator.validate_safe_input(user_input):
    # Input is safe
    pass
```

### Sanitize Strings
```python
# Sanitize user input
clean_input = validator.sanitize_string(
    value=user_input,
    max_length=1000,
    strip_html=True
)
```

## 3. Tenant Isolation

### Enforce Strict Isolation
```python
from mem0_governance.tenant import TenantManager

tenant_mgr = TenantManager()

# Always validate tenant access
can_access = tenant_mgr.validate_tenant_access(
    tenant_id=current_tenant,
    resource_tenant_id=resource_tenant
)

if not can_access:
    raise PermissionError("Cross-tenant access denied")
```

### Set Tenant Context
```python
# Set tenant context at request start
tenant_mgr.set_current_tenant(request.tenant_id)

# Clear tenant context at request end
tenant_mgr.clear_current_tenant()
```

## 4. RBAC Enforcement

### Check Permissions Before Operations
```python
from mem0_governance.rbac import RBACManager, Permission

rbac = RBACManager()

# Check permission before action
if not rbac.check_permission(
    subject_id=user_id,
    permission=Permission.MEMORY_WRITE,
    tenant_id=tenant_id
):
    # Log denial
    audit_logger.log_event(
        event_type=AuditEventType.SECURITY_ACCESS_DENIED,
        actor_id=user_id,
        actor_name=user_name,
        action="write_memory",
        result="denied",
        tenant_id=tenant_id,
    )
    raise PermissionError("Insufficient permissions")
```

### Principle of Least Privilege
- Assign minimum required roles
- Use specific permissions, not wildcards
- Regular permission audits
- Remove unused roles promptly

## 5. Policy Enforcement

### Deny-by-Default Policies
```yaml
# Every policy should have explicit allows
statements:
  # Explicit allow
  - effect: "allow"
    actions: ["memory:read"]
    resources: ["memory:tenant:${tenant_id}:*"]
  
  # Explicit deny for sensitive operations
  - effect: "deny"
    actions: ["memory:delete"]
    resources: ["memory:tenant:*:critical-*"]
```

### Policy Evaluation
```python
from mem0_governance.policy import PolicyEngine, PolicyDecision

policy_engine = PolicyEngine()

# Evaluate before allowing operation
decision = policy_engine.evaluate(
    action="memory:read",
    resource=f"memory:tenant:{tenant_id}:{memory_id}",
    context={
        "tenant_id": tenant_id,
        "user_id": user_id,
        "source_ip": request.remote_addr,
    }
)

if decision == PolicyDecision.DENIED:
    raise PermissionError("Policy denied access")
```

## 6. Audit Logging

### Log All Security Events
```python
from mem0_governance.audit import AuditLogger, AuditEventType, AuditSeverity

audit_logger = AuditLogger()

# Log authentication
audit_logger.log_event(
    event_type=AuditEventType.AUTH_LOGIN,
    actor_id=user_id,
    actor_name=username,
    action="login",
    result="success",
    tenant_id=tenant_id,
    source_ip=request.remote_addr,
    session_id=session_id,
)

# Log security violations
audit_logger.log_event(
    event_type=AuditEventType.SECURITY_VIOLATION,
    actor_id=user_id,
    actor_name=username,
    action="suspicious_activity",
    result="blocked",
    severity=AuditSeverity.CRITICAL,
    details={"reason": "Multiple failed login attempts"},
    source_ip=request.remote_addr,
)
```

### Verify Audit Log Integrity
```python
# Regular integrity checks
is_valid = audit_logger.verify_integrity()
if not is_valid:
    # Alert security team
    alert_security_team("Audit log tampering detected!")
```

## 7. Rate Limiting

### Protect Against Abuse
```python
from mem0_governance.security import RateLimiter

rate_limiter = RateLimiter(
    max_requests=100,  # 100 requests
    window_seconds=60,  # per minute
)

# Check rate limit
if not rate_limiter.check_rate_limit(identifier=user_id):
    audit_logger.log_event(
        event_type=AuditEventType.SECURITY_VIOLATION,
        actor_id=user_id,
        actor_name=username,
        action="rate_limit_exceeded",
        result="blocked",
        severity=AuditSeverity.WARNING,
    )
    raise RateLimitError("Too many requests")
```

## 8. Configuration Security

### Separate Secrets from Config
```yaml
# config.yaml - Non-sensitive settings only
rbac_enabled: true
tenant_isolation_enabled: true
audit_retention_days: 365

# ❌ NEVER put secrets in config files
# api_key: "sk-123..."  # WRONG!
```

```bash
# .env - Secrets (NEVER commit to git)
MEM0_GOV_API_KEY=sk-your-secret-key
MEM0_GOV_DB_PASSWORD=your-password

# Add .env to .gitignore
echo ".env" >> .gitignore
```

## 9. Secure Deployment

### Production Checklist
- [ ] All secrets in environment variables or vault
- [ ] TLS/SSL enabled for all connections
- [ ] Audit logs stored in secure, immutable storage
- [ ] Regular security audits scheduled
- [ ] Monitoring and alerting configured
- [ ] Backup and disaster recovery tested
- [ ] Least privilege access controls
- [ ] Network segmentation implemented
- [ ] Regular dependency updates
- [ ] Penetration testing completed

### Environment Variables
```bash
# Required security settings
export MEM0_GOV_RBAC_ENABLED=true
export MEM0_GOV_TENANT_ISOLATION_ENABLED=true
export MEM0_GOV_POLICY_ENGINE_ENABLED=true
export MEM0_GOV_AUDIT_ENABLED=true
export MEM0_GOV_DENY_BY_DEFAULT=true
export MEM0_GOV_REQUIRE_SECURE_SECRETS=true

# Secrets (from vault)
export MEM0_GOV_API_KEY=$(vault read secret/mem0/api-key)
export MEM0_GOV_DB_PASSWORD=$(vault read secret/mem0/db-password)
```

## 10. Incident Response

### Security Event Monitoring
```python
# Monitor for critical security events
critical_events = audit_logger.get_events(
    event_type=AuditEventType.SECURITY_VIOLATION,
    severity=AuditSeverity.CRITICAL,
)

for event in critical_events:
    # Alert security team
    send_alert(event)
```

### Breach Response
1. **Detect**: Monitor audit logs for suspicious activity
2. **Contain**: Revoke compromised credentials immediately
3. **Investigate**: Export audit logs for forensics
4. **Remediate**: Patch vulnerabilities, rotate secrets
5. **Report**: Notify affected parties and authorities as required

### Audit Log Export for Investigation
```python
# Export audit logs for forensic analysis
logs = audit_logger.export_events(
    format="json",
    tenant_id=affected_tenant,
    start_time=incident_start,
    end_time=incident_end,
)

# Store securely for investigation
with open("incident_logs.json", "w") as f:
    f.write(logs)
```

## 11. Dependency Security

### License Compliance
All dependencies are Apache-2.0 compatible:
- ✅ pydantic: MIT License
- ✅ pyyaml: MIT License
- ✅ cryptography: Apache-2.0 / BSD
- ✅ python-dotenv: BSD-3-Clause

### Regular Updates
```bash
# Check for security updates
pip list --outdated

# Update dependencies
pip install --upgrade -r requirements.txt

# Audit for vulnerabilities
pip-audit
```

## 12. Testing Security

### Security Testing
```python
# Test input validation
def test_sql_injection_prevention():
    validator = InputValidator()
    malicious_input = "'; DROP TABLE users; --"
    assert validator.check_sql_injection(malicious_input)

# Test RBAC
def test_deny_by_default():
    rbac = RBACManager()
    user = rbac.create_subject("user1", "Test User")  # No roles
    assert not rbac.check_permission("user1", Permission.MEMORY_READ)

# Test tenant isolation
def test_cross_tenant_access_denied():
    tenant_mgr = TenantManager()
    assert not tenant_mgr.validate_tenant_access("tenant-a", "tenant-b")
```

## Contact

For security issues, please report to: security@[your-domain]

**Do not disclose security vulnerabilities publicly until they are patched.**
