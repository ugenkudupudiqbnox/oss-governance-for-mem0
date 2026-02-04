package mem0.authz

# Admin: full access
allow if {
  "admin" in input.roles
}

# Reader: read-only, same tenant
allow if {
  input.action == "read"
  "agent-reader" in input.roles
  input.tenant == input.resource_tenant
}

# Writer: read + write, same tenant
allow if {
  input.action == "read"
  "agent-writer" in input.roles
  input.tenant == input.resource_tenant
}

allow if {
  input.action == "write"
  "agent-writer" in input.roles
  input.tenant == input.resource_tenant
}

# Auditor: audit logs only
allow if {
  input.action == "audit_read"
  "auditor" in input.roles
}
