CREATE TABLE mem0_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_id TEXT NOT NULL,
    actor_role TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_id TEXT,
    decision TEXT NOT NULL,
    source_ip TEXT
);

CREATE INDEX idx_mem0_audit_time ON mem0_audit_log(timestamp);
CREATE INDEX idx_mem0_audit_actor ON mem0_audit_log(actor_id);
