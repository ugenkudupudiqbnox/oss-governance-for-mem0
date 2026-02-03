# Policy-as-Code

This directory contains policy definitions for the Governance Pack for Mem0. Policies are written as code to enable version control, testing, and automated enforcement.

## Overview

The governance pack uses a **deny-by-default** security model:
- All access is denied unless explicitly allowed by policy
- Policies are evaluated before any operation reaches Mem0
- Policy decisions are logged in the audit trail

## Policy Language

Policies are written in [Open Policy Agent (OPA) Rego](https://www.openpolicyagent.org/docs/latest/policy-language/), an industry-standard policy-as-code language.

### Why OPA/Rego?

- **Declarative**: Express what should be allowed, not how to enforce it
- **Testable**: Write unit tests for policies
- **Version-controlled**: Track policy changes in Git
- **Standard**: Widely adopted in cloud-native security
- **Flexible**: Supports complex authorization logic

## Available Policies

- [access_control.rego](./access_control.rego) - Main access control policy with deny-by-default

## Policy Structure

### Decision Flow

```
Request → Policy Engine → Decision (allow/deny) → Audit Log → Mem0 (if allowed)
```

### Policy Evaluation

1. **Authentication**: Verify user identity
2. **Authorization**: Check user permissions
3. **Data Classification**: Validate data sensitivity
4. **Context**: Consider time, location, device
5. **Decision**: Allow or deny with reason

## Quick Start

### Installing OPA

```bash
# macOS
brew install opa

# Linux
curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64
chmod +x opa
sudo mv opa /usr/local/bin/

# Windows
# Download from https://www.openpolicyagent.org/downloads/
```

### Testing a Policy

```bash
# Validate policy syntax
opa check access_control.rego

# Run policy tests
opa test . -v

# Evaluate a policy with input
opa eval -d access_control.rego -i input.json "data.mem0.access.allow"
```

### Example Input

```json
{
  "user": {
    "id": "user123",
    "role": "analyst",
    "department": "engineering"
  },
  "operation": "mem0_search",
  "resource": {
    "type": "memory",
    "id": "mem_456",
    "classification": "internal"
  },
  "context": {
    "ip": "10.0.1.50",
    "time": "2026-02-03T14:30:00Z"
  }
}
```

## Writing Policies

### Basic Policy Pattern

```rego
package mem0.access

# Deny by default
default allow = false

# Allow if all conditions are met
allow {
    is_authenticated
    has_permission
    within_business_hours
}

# Helper rules
is_authenticated {
    input.user.id != ""
}

has_permission {
    input.user.role == "admin"
}

within_business_hours {
    # Implement your logic
}
```

### Best Practices

1. **Deny by Default**: Start with `default allow = false`
2. **Explicit Rules**: Each allow condition should be explicit and clear
3. **Separation**: Separate authentication, authorization, and business logic
4. **Documentation**: Comment complex rules
5. **Testing**: Write tests for all policy paths
6. **Least Privilege**: Grant minimum necessary permissions
7. **Audit**: Log all policy decisions with reasons

## Policy Testing

### Unit Tests

Create a file `access_control_test.rego`:

```rego
package mem0.access

test_deny_by_default {
    not allow with input as {}
}

test_admin_can_access {
    allow with input as {
        "user": {"id": "admin1", "role": "admin"},
        "operation": "mem0_search"
    }
}

test_user_cannot_access_restricted {
    not allow with input as {
        "user": {"id": "user1", "role": "user"},
        "resource": {"classification": "restricted"}
    }
}
```

Run tests:
```bash
opa test . -v
```

## Integration

### Python Example

```python
from opa_client import OpaClient

# Initialize OPA client
opa = OpaClient(host="localhost", port=8181)

# Load policy
with open("policies/access_control.rego", "r") as f:
    opa.update_policy("access_control", f.read())

# Evaluate policy
input_data = {
    "user": {"id": "user123", "role": "analyst"},
    "operation": "mem0_search",
    "resource": {"classification": "internal"}
}

result = opa.check_permission(
    input_data=input_data,
    policy_name="access_control",
    rule_name="allow"
)

if result["result"]:
    # Access allowed
    execute_mem0_operation()
else:
    # Access denied
    log_denied_access(result.get("reason"))
```

### Go Example

```go
package main

import (
    "context"
    "github.com/open-policy-agent/opa/rego"
)

func checkAccess(userID, operation string) (bool, error) {
    ctx := context.Background()
    
    // Load policy
    query := rego.New(
        rego.Query("data.mem0.access.allow"),
        rego.Load([]string{"policies/access_control.rego"}, nil),
    )
    
    // Evaluate with input
    input := map[string]interface{}{
        "user": map[string]interface{}{
            "id": userID,
        },
        "operation": operation,
    }
    
    rs, err := query.Eval(ctx, rego.EvalInput(input))
    if err != nil {
        return false, err
    }
    
    return rs.Allowed(), nil
}
```

## Deployment

### Development

Run OPA server locally:
```bash
opa run --server --addr localhost:8181 policies/
```

### Production

For production deployments:

1. **High Availability**: Run multiple OPA instances behind a load balancer
2. **Policy Updates**: Use OPA's bundle API for atomic policy updates
3. **Caching**: Enable decision caching for performance
4. **Monitoring**: Monitor policy evaluation latency
5. **Security**: Secure OPA API with TLS and authentication

### Docker

```dockerfile
FROM openpolicyagent/opa:latest
COPY policies/ /policies/
CMD ["run", "--server", "--addr", "0.0.0.0:8181", "/policies"]
```

```bash
docker build -t mem0-governance-policy .
docker run -p 8181:8181 mem0-governance-policy
```

## Policy Versioning

Policies are versioned via Git:

```bash
# View policy history
git log --oneline policies/access_control.rego

# Compare versions
git diff v1.0.0 v1.1.0 -- policies/access_control.rego

# Tag policy releases
git tag -a policy-v1.0.0 -m "Release access control policy v1.0.0"
```

Include the policy version in audit logs:
```python
audit_log.record(
    user_id=user_id,
    operation=operation,
    result=result,
    policy_version="v1.0.0",
    policy_decision_reason=reason
)
```

## Common Patterns

### Role-Based Access Control (RBAC)

```rego
# Define role permissions
role_permissions := {
    "admin": {"read", "write", "delete"},
    "analyst": {"read", "write"},
    "viewer": {"read"}
}

# Check if user's role has required permission
has_permission {
    required := input.required_permission
    user_perms := role_permissions[input.user.role]
    required in user_perms
}
```

### Data Classification

```rego
# Define who can access what classification
classification_access := {
    "restricted": {"admin", "security_officer"},
    "confidential": {"admin", "analyst", "manager"},
    "internal": {"admin", "analyst", "user"},
    "public": {"admin", "analyst", "user", "guest"}
}

# Check access based on classification
can_access_classification {
    classification := input.resource.classification
    role := input.user.role
    allowed_roles := classification_access[classification]
    role in allowed_roles
}
```

### Time-Based Access

```rego
# Business hours only
within_business_hours {
    time := time.parse_rfc3339_ns(input.context.time)
    hour := time[1]  # hour of day
    day := time[2]   # day of week (0=Sunday)
    
    hour >= 8
    hour < 18
    day >= 1  # Monday
    day <= 5  # Friday
}
```

### Rate Limiting

```rego
# Example: Check rate limit (requires external data)
within_rate_limit {
    user_id := input.user.id
    window := "1h"
    limit := 1000
    
    # Query rate limit service or cache
    current := http.send({
        "method": "GET",
        "url": sprintf("http://ratelimit-service/check/%s/%s", [user_id, window])
    }).body.count
    
    current < limit
}
```

## Troubleshooting

### Policy Not Loading

```bash
# Check syntax
opa check policies/access_control.rego

# Run with verbose logging
opa run --server --log-level=debug policies/
```

### Unexpected Denials

```bash
# Evaluate with decision logs
opa eval --explain=notes -d access_control.rego -i input.json "data.mem0.access.allow"

# Check which rules are matching
opa eval --explain=full -d access_control.rego -i input.json "data.mem0.access"
```

### Performance Issues

- Enable caching in OPA
- Pre-compute complex rules
- Use indexes for large datasets
- Profile policy evaluation

## Security Considerations

1. **Policy Access**: Restrict who can modify policies
2. **Secrets**: Never hardcode secrets in policies (use external data)
3. **Testing**: Test all policy paths including edge cases
4. **Versioning**: Track all policy changes
5. **Review**: Require peer review for policy changes
6. **Separation**: Policy authors should not be system operators

## Resources

- [OPA Documentation](https://www.openpolicyagent.org/docs/latest/)
- [Rego Playground](https://play.openpolicyagent.org/)
- [Policy Reference](https://www.openpolicyagent.org/docs/latest/policy-reference/)
- [Best Practices](https://www.openpolicyagent.org/docs/latest/policy-performance/)

## Support

For questions about policies:
- Review [Examples](./access_control.rego)
- Check [OPA Documentation](https://www.openpolicyagent.org/docs/)
- Open a GitHub issue
