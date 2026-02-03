package mem0.authz

# Deny by default
default allow = false

# Allow admins full access
allow {
  "admin" in input.roles
}

# Allow read access
allow {
  input.action == "read"
  "agent-reader" in input.roles
}

# Allow write access
allow {
  input.action == "write"
  "agent-writer" in input.roles
}

# Enforce tenant isolation
allow {
  input.tenant == input.resource_tenant
}
