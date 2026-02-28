INSERT INTO mem0_audit_log (actor_id, actor_role, tenant_id, action, resource_id, decision, source_ip, timestamp)
VALUES
  ('agent-001', 'agent-writer', 'tenantA', 'write', 'ticket-123', 'allow', '127.0.0.1', NOW()),
  ('agent-002', 'agent-reader', 'tenantA', 'read', 'ticket-123', 'allow', '127.0.0.1', NOW()),
  ('auditor-001', 'auditor', 'tenantA', 'audit_read', 'audit', 'allow', '127.0.0.1', NOW()),
  ('agent-003', 'agent-writer', 'tenantB', 'write', 'ticket-456', 'deny', '127.0.0.1', NOW());
