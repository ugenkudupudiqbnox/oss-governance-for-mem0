package mem0.authz

# Default deny
default allow = false

# Admin: full access
allow {
  "admin" in input.roles
}

# Reader: read-only access
allow {
  input.action == "read"
  "agent-reader" in input.roles
  input.tenant == input.resource_tenant
}

# Writer: read and write access
allow {
  input.action == "write"
  "agent-writer" in input.roles
  input.tenant == input.resource_tenant
}

allow {
  input.action == "read"
  "agent-writer" in input.roles
  input.tenant == input.resource_tenant
}

# Auditor: read audit logs only
allow {
  input.action == "audit_read"
  "auditor" in input.roles
}
