-- Governance Pack for Mem0 - Audit Log Schema
-- PostgreSQL 12+
--
-- This schema provides comprehensive audit logging for all operations
-- related to Mem0 integration, designed for SOC 2 and ISO 27001 compliance.
--
-- Features:
-- - Immutable audit trail (append-only)
-- - Comprehensive context capture
-- - Performance-optimized indexes
-- - Compliance-ready structure
-- - Optional cryptographic signatures

-- Create extension for UUID generation if not exists
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Main audit log table
CREATE TABLE IF NOT EXISTS audit_logs (
    -- Unique identifier for each audit record
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Timestamp of the event (UTC)
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- User identification
    user_id VARCHAR(255) NOT NULL,
    user_role VARCHAR(100),
    session_id VARCHAR(255),
    
    -- Operation details
    operation VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100),
    resource_id VARCHAR(255),
    action_result VARCHAR(50) NOT NULL CHECK (action_result IN ('allowed', 'denied', 'error', 'pending')),
    
    -- Request context
    ip_address INET,
    user_agent TEXT,
    request_id VARCHAR(255),
    
    -- Data classification and volume
    data_classification VARCHAR(50) CHECK (data_classification IN ('public', 'internal', 'confidential', 'restricted', 'unknown')),
    data_size_bytes BIGINT,
    
    -- Mem0-specific fields
    mem0_operation VARCHAR(100),
    mem0_response_code INTEGER,
    mem0_latency_ms INTEGER,
    
    -- Additional context (flexible JSON field)
    details JSONB DEFAULT '{}',
    
    -- Optional cryptographic signature for tamper detection
    signature VARCHAR(512),
    
    -- Policy evaluation details
    policy_version VARCHAR(50),
    policy_decision_reason TEXT,
    
    -- Constraints
    CONSTRAINT valid_timestamp CHECK (timestamp <= NOW() + INTERVAL '1 minute')
);

-- Indexes for common query patterns

-- Most common: lookup by user and time range
CREATE INDEX idx_audit_logs_user_timestamp 
    ON audit_logs(user_id, timestamp DESC);

-- Lookup by timestamp (for time-based queries and partitioning)
CREATE INDEX idx_audit_logs_timestamp 
    ON audit_logs(timestamp DESC);

-- Lookup by operation type
CREATE INDEX idx_audit_logs_operation 
    ON audit_logs(operation, timestamp DESC);

-- Lookup by result (especially for denied access)
CREATE INDEX idx_audit_logs_result 
    ON audit_logs(action_result, timestamp DESC);

-- Lookup by resource
CREATE INDEX idx_audit_logs_resource 
    ON audit_logs(resource_type, resource_id, timestamp DESC);

-- Lookup by request ID (for tracing related operations)
CREATE INDEX idx_audit_logs_request_id 
    ON audit_logs(request_id) WHERE request_id IS NOT NULL;

-- Lookup by data classification (for compliance reports)
CREATE INDEX idx_audit_logs_classification 
    ON audit_logs(data_classification, timestamp DESC) WHERE data_classification IS NOT NULL;

-- GIN index for JSON details (for flexible querying)
CREATE INDEX idx_audit_logs_details 
    ON audit_logs USING GIN(details);

-- Create a view for common audit queries
CREATE OR REPLACE VIEW audit_logs_summary AS
SELECT 
    user_id,
    user_role,
    operation,
    action_result,
    COUNT(*) as event_count,
    MIN(timestamp) as first_seen,
    MAX(timestamp) as last_seen,
    SUM(data_size_bytes) as total_data_bytes
FROM audit_logs
WHERE timestamp >= NOW() - INTERVAL '30 days'
GROUP BY user_id, user_role, operation, action_result;

-- Create a view for denied access attempts
CREATE OR REPLACE VIEW denied_access_attempts AS
SELECT 
    timestamp,
    user_id,
    user_role,
    operation,
    resource_type,
    resource_id,
    ip_address,
    policy_decision_reason,
    details
FROM audit_logs
WHERE action_result = 'denied'
ORDER BY timestamp DESC;

-- Create a view for privileged operations
CREATE OR REPLACE VIEW privileged_operations AS
SELECT 
    timestamp,
    user_id,
    user_role,
    operation,
    resource_id,
    action_result,
    details
FROM audit_logs
WHERE user_role IN ('admin', 'security_officer', 'auditor')
   OR operation IN ('policy_change', 'user_create', 'user_delete', 'role_change')
ORDER BY timestamp DESC;

-- Function to prevent updates and deletes (immutability enforcement)
CREATE OR REPLACE FUNCTION prevent_audit_log_modification()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION 'Updates to audit_logs are not permitted';
    END IF;
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Deletions from audit_logs are not permitted';
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Trigger to enforce immutability
CREATE TRIGGER audit_logs_immutability
    BEFORE UPDATE OR DELETE ON audit_logs
    FOR EACH ROW
    EXECUTE FUNCTION prevent_audit_log_modification();

-- Function to calculate signature (example - implement proper HMAC in production)
CREATE OR REPLACE FUNCTION calculate_audit_signature(
    p_id UUID,
    p_timestamp TIMESTAMPTZ,
    p_user_id VARCHAR,
    p_operation VARCHAR,
    p_secret VARCHAR
) RETURNS VARCHAR AS $$
BEGIN
    -- This is a simple example. In production, use proper HMAC-SHA256
    -- with a securely stored secret key, possibly using pgcrypto extension
    RETURN encode(
        digest(
            p_id::TEXT || 
            p_timestamp::TEXT || 
            p_user_id || 
            p_operation || 
            p_secret,
            'sha256'
        ),
        'hex'
    );
END;
$$ LANGUAGE plpgsql;

-- Table for tracking audit log archival
CREATE TABLE IF NOT EXISTS audit_log_archives (
    id SERIAL PRIMARY KEY,
    archive_date DATE NOT NULL,
    records_archived INTEGER NOT NULL,
    start_timestamp TIMESTAMPTZ NOT NULL,
    end_timestamp TIMESTAMPTZ NOT NULL,
    archive_location TEXT NOT NULL,
    checksum VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(archive_date, start_timestamp, end_timestamp)
);

-- Create a dedicated role for audit logging (least privilege)
-- Note: Uncomment and modify for your environment
-- CREATE ROLE audit_logger;
-- GRANT INSERT ON audit_logs TO audit_logger;
-- GRANT SELECT ON audit_logs TO audit_logger;
-- REVOKE UPDATE, DELETE, TRUNCATE ON audit_logs FROM audit_logger;

-- Create a dedicated role for audit readers (analysts, compliance team)
-- Note: Uncomment and modify for your environment
-- CREATE ROLE audit_reader;
-- GRANT SELECT ON audit_logs TO audit_reader;
-- GRANT SELECT ON audit_logs_summary TO audit_reader;
-- GRANT SELECT ON denied_access_attempts TO audit_reader;
-- GRANT SELECT ON privileged_operations TO audit_reader;

-- Comments for documentation
COMMENT ON TABLE audit_logs IS 'Immutable audit log for all governance pack operations';
COMMENT ON COLUMN audit_logs.id IS 'Unique identifier for each audit record';
COMMENT ON COLUMN audit_logs.timestamp IS 'UTC timestamp when the event occurred';
COMMENT ON COLUMN audit_logs.user_id IS 'Identifier of the user performing the action';
COMMENT ON COLUMN audit_logs.operation IS 'Type of operation performed (e.g., mem0_search, policy_check)';
COMMENT ON COLUMN audit_logs.action_result IS 'Outcome of the operation: allowed, denied, error, or pending';
COMMENT ON COLUMN audit_logs.data_classification IS 'Sensitivity level of data involved in the operation';
COMMENT ON COLUMN audit_logs.details IS 'Flexible JSON field for additional operation context';
COMMENT ON COLUMN audit_logs.signature IS 'Optional cryptographic signature for tamper detection';
COMMENT ON COLUMN audit_logs.policy_version IS 'Version of policy that was evaluated';
COMMENT ON COLUMN audit_logs.policy_decision_reason IS 'Explanation of why the policy allowed or denied access';

-- Example data for testing (optional - remove in production)
-- INSERT INTO audit_logs (user_id, user_role, operation, resource_type, resource_id, action_result, data_classification, details)
-- VALUES 
--     ('user123', 'user', 'mem0_search', 'memory', 'mem_456', 'allowed', 'internal', '{"query": "recent conversations", "results_count": 5}'),
--     ('user456', 'user', 'mem0_add', 'memory', 'mem_789', 'allowed', 'confidential', '{"content_length": 150}'),
--     ('user789', 'user', 'mem0_delete', 'memory', 'mem_321', 'denied', 'restricted', '{"reason": "insufficient permissions"}'),
--     ('admin1', 'admin', 'policy_change', 'policy', 'access_control.rego', 'allowed', 'internal', '{"change_type": "add_rule", "rule_name": "require_mfa"}');

-- Table statistics for query planning
ANALYZE audit_logs;

-- Success message
DO $$
BEGIN
    RAISE NOTICE 'Audit log schema created successfully!';
    RAISE NOTICE 'Next steps:';
    RAISE NOTICE '  1. Configure your application to insert audit logs';
    RAISE NOTICE '  2. Set up backup and retention policies';
    RAISE NOTICE '  3. Create database roles for audit_logger and audit_reader';
    RAISE NOTICE '  4. Review and test common audit queries';
    RAISE NOTICE '  5. Consider implementing table partitioning for large-scale deployments';
END $$;
