# Governance Pack for Mem0

**Open-source governance, security, audit, and compliance controls for Mem0 (OSS)**

> ⚠️ **Important**: This is a companion governance layer for Mem0. It does NOT modify Mem0 or imply any affiliation with the Mem0 project. This package is designed for enterprise, regulated, and multi-tenant deployments requiring enhanced security and compliance controls.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

## 🎯 Overview

The Mem0 Governance Pack provides enterprise-grade security, audit, and compliance controls for organizations using Mem0 in regulated environments. It prioritizes:

- **Security First**: Deny-by-default policies, tenant isolation, no hard-coded secrets
- **Auditability**: Immutable audit logs with cryptographic integrity verification
- **Compliance**: Policy-as-code, RBAC, explicit logging for regulatory requirements
- **Multi-Tenancy**: Strict tenant isolation for SaaS and multi-customer deployments

## 🚀 Key Features

### 1. **RBAC (Role-Based Access Control)**
- Predefined roles: Admin, Auditor, User, ReadOnly, Guest
- Fine-grained permissions for all operations
- Deny-by-default access control
- Tenant-scoped role assignments

### 2. **Tenant Isolation**
- Strict data separation between tenants
- Tenant context management
- Cross-tenant access prevention
- Resource limits per tenant

### 3. **Deny-by-Default Policies**
- Policy-as-code (YAML/JSON)
- Explicit allow rules required
- Policy evaluation engine
- Hierarchical policy structure

### 4. **Immutable Audit Logs**
- Append-only audit trail
- Cryptographic hash chaining for integrity
- Comprehensive event logging
- Tamper detection
- Export capabilities for compliance

### 5. **Security Features**
- No hard-coded secrets (environment-based)
- Input validation and sanitization
- Rate limiting
- Secret strength validation
- SQL injection and XSS prevention

## 📦 Installation

```bash
pip install -e .
```

For development:
```bash
pip install -e ".[dev]"
```

## 🔧 Quick Start

### Basic Usage

```python
from mem0_governance import (
    RBACManager, Role, Permission,
    TenantManager, TenantStatus,
    PolicyEngine, Policy,
    AuditLogger, AuditEventType, AuditSeverity,
    SecretManager, InputValidator,
)
from mem0_governance.config import GovernanceConfig

# Load configuration from environment
config = GovernanceConfig.from_env()

# Initialize components
rbac = RBACManager()
tenant_mgr = TenantManager()
policy_engine = PolicyEngine()
audit_logger = AuditLogger()
secret_mgr = SecretManager()

# Create a tenant
tenant = tenant_mgr.create_tenant(
    tenant_id="acme-corp",
    name="ACME Corporation",
    status=TenantStatus.ACTIVE,
)

# Create a user with role
user = rbac.create_subject(
    subject_id="user123",
    name="John Doe",
    roles={Role.USER},
    tenant_id="acme-corp",
)

# Check permissions
can_read = rbac.check_permission(
    subject_id="user123",
    permission=Permission.MEMORY_READ,
    tenant_id="acme-corp",
)

# Log audit event
audit_logger.log_event(
    event_type=AuditEventType.MEMORY_READ,
    actor_id="user123",
    actor_name="John Doe",
    action="read_memory",
    result="success",
    tenant_id="acme-corp",
    resource_type="memory",
    resource_id="mem456",
)

# Load and evaluate policies
policy_engine.load_policies_from_directory("./policies")
decision = policy_engine.evaluate(
    action="memory:read",
    resource="memory:tenant:acme-corp:mem456",
    context={"tenant_id": "acme-corp"},
)
```

### Configuration

Configuration can be loaded from environment variables or config files:

```python
# From environment variables (recommended for production)
config = GovernanceConfig.from_env(prefix="MEM0_GOV_")

# From YAML file (for non-secret settings)
config = GovernanceConfig.from_file("config.yaml")
```

**Environment Variables:**
```bash
# RBAC
export MEM0_GOV_RBAC_ENABLED=true
export MEM0_GOV_DEFAULT_ROLE=guest

# Tenancy
export MEM0_GOV_TENANT_ISOLATION_ENABLED=true

# Policies
export MEM0_GOV_POLICY_ENGINE_ENABLED=true
export MEM0_GOV_POLICY_DIRECTORY=./policies
export MEM0_GOV_DENY_BY_DEFAULT=true

# Audit
export MEM0_GOV_AUDIT_ENABLED=true
export MEM0_GOV_AUDIT_RETENTION_DAYS=365

# Security
export MEM0_GOV_REQUIRE_SECURE_SECRETS=true
export MEM0_GOV_MIN_SECRET_LENGTH=32
export MEM0_GOV_RATE_LIMIT_ENABLED=true
```

## 📚 Documentation

- [Architecture Overview](docs/ARCHITECTURE.md)
- [Security Guidelines](docs/SECURITY.md)
- [Compliance Guide](docs/COMPLIANCE.md)
- [API Reference](docs/API.md)
- [Policy Examples](policies/examples/)

## 🔐 Security Considerations

### No Hard-Coded Secrets
All secrets must be provided via environment variables:
```python
secret_mgr = SecretManager(prefix="MEM0_GOV_")
api_key = secret_mgr.get_secret("API_KEY")
```

### Deny-by-Default
All access is denied unless explicitly allowed by policy:
```yaml
# policies/my-policy.yaml
statements:
  - effect: "allow"  # Explicit allow required
    actions: ["memory:read"]
    resources: ["memory:tenant:acme:*"]
```

### Tenant Isolation
Strict separation between tenants is enforced:
```python
# Access is denied if tenant_id doesn't match
can_access = tenant_mgr.validate_tenant_access(
    tenant_id="tenant-a",
    resource_tenant_id="tenant-b",  # Returns False
)
```

### Immutable Audit Logs
Audit events cannot be modified once created:
```python
# Events are chained with cryptographic hashes
event = audit_logger.log_event(...)

# Verify integrity
is_valid = audit_logger.verify_integrity()  # True if no tampering
```

## 🧪 Testing

Run tests:
```bash
pytest tests/
```

With coverage:
```bash
pytest --cov=mem0_governance tests/
```

## 📋 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

All dependencies are compatible with Apache-2.0 license:
- pydantic: MIT License
- pyyaml: MIT License
- cryptography: Apache-2.0 / BSD
- python-dotenv: BSD-3-Clause

## 🤝 Contributing

Contributions are welcome! Please ensure:
1. All tests pass
2. Code follows existing style
3. No hard-coded secrets
4. Security-first approach
5. Comprehensive audit logging

## ⚠️ Disclaimer

This is an independent governance layer for Mem0. It is NOT affiliated with, endorsed by, or part of the official Mem0 project. Use at your own risk. Always conduct security audits before production deployment.

## 🔗 Related Projects

- [Mem0](https://github.com/mem0ai/mem0) - The memory layer for AI applications

## 📞 Support

For issues, questions, or contributions, please open an issue on GitHub.

---

**Built for enterprise, regulated, and multi-tenant deployments**