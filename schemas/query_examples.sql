-- Common Audit Log Queries
-- Examples for compliance reporting and security monitoring

-- ============================================================================
-- COMPLIANCE QUERIES
-- ============================================================================

-- 1. Access summary by user (last 30 days)
SELECT 
    user_id,
    user_role,
    COUNT(*) as total_operations,
    COUNT(DISTINCT operation) as unique_operations,
    COUNT(*) FILTER (WHERE action_result = 'allowed') as allowed,
    COUNT(*) FILTER (WHERE action_result = 'denied') as denied,
    MIN(timestamp) as first_access,
    MAX(timestamp) as last_access
FROM audit_logs
WHERE timestamp >= NOW() - INTERVAL '30 days'
GROUP BY user_id, user_role
ORDER BY total_operations DESC;

-- 2. Failed access attempts by user
SELECT 
    user_id,
    operation,
    resource_type,
    COUNT(*) as failure_count,
    ARRAY_AGG(DISTINCT ip_address) as source_ips,
    MAX(timestamp) as last_failure
FROM audit_logs
WHERE action_result = 'denied'
  AND timestamp >= NOW() - INTERVAL '7 days'
GROUP BY user_id, operation, resource_type
HAVING COUNT(*) >= 3
ORDER BY failure_count DESC;

-- 3. Privileged operations audit trail
SELECT 
    timestamp,
    user_id,
    user_role,
    operation,
    resource_type,
    resource_id,
    action_result,
    policy_decision_reason
FROM audit_logs
WHERE operation IN ('policy_change', 'user_create', 'user_delete', 'role_change', 'admin_access')
   OR user_role IN ('admin', 'security_officer')
  AND timestamp >= NOW() - INTERVAL '90 days'
ORDER BY timestamp DESC
LIMIT 100;

-- 4. Data access by classification level
SELECT 
    data_classification,
    COUNT(*) as access_count,
    COUNT(DISTINCT user_id) as unique_users,
    SUM(data_size_bytes) as total_bytes,
    pg_size_pretty(SUM(data_size_bytes)) as total_size,
    COUNT(*) FILTER (WHERE action_result = 'denied') as blocked_attempts
FROM audit_logs
WHERE timestamp >= NOW() - INTERVAL '30 days'
  AND data_classification IS NOT NULL
GROUP BY data_classification
ORDER BY 
    CASE data_classification
        WHEN 'restricted' THEN 1
        WHEN 'confidential' THEN 2
        WHEN 'internal' THEN 3
        WHEN 'public' THEN 4
        ELSE 5
    END;

-- 5. User access pattern timeline (daily summary)
SELECT 
    DATE(timestamp) as access_date,
    user_id,
    COUNT(*) as operations,
    COUNT(*) FILTER (WHERE action_result = 'denied') as denials,
    COUNT(DISTINCT operation) as unique_operations,
    MIN(EXTRACT(HOUR FROM timestamp)) as earliest_hour,
    MAX(EXTRACT(HOUR FROM timestamp)) as latest_hour
FROM audit_logs
WHERE timestamp >= NOW() - INTERVAL '30 days'
GROUP BY access_date, user_id
ORDER BY access_date DESC, operations DESC;

-- ============================================================================
-- SECURITY MONITORING QUERIES
-- ============================================================================

-- 6. Suspicious activity: High volume of denied requests
SELECT 
    user_id,
    ip_address,
    operation,
    COUNT(*) as denied_count,
    MIN(timestamp) as first_denial,
    MAX(timestamp) as last_denial,
    MAX(timestamp) - MIN(timestamp) as time_span
FROM audit_logs
WHERE action_result = 'denied'
  AND timestamp >= NOW() - INTERVAL '1 hour'
GROUP BY user_id, ip_address, operation
HAVING COUNT(*) > 10
ORDER BY denied_count DESC;

-- 7. Off-hours access (outside business hours)
SELECT 
    user_id,
    user_role,
    DATE(timestamp) as date,
    COUNT(*) as off_hours_operations,
    ARRAY_AGG(DISTINCT operation) as operations_performed,
    ARRAY_AGG(DISTINCT EXTRACT(HOUR FROM timestamp)::INTEGER) as hours_active
FROM audit_logs
WHERE (
    EXTRACT(HOUR FROM timestamp) NOT BETWEEN 8 AND 18
    OR EXTRACT(DOW FROM timestamp) NOT BETWEEN 1 AND 5
)
  AND timestamp >= NOW() - INTERVAL '7 days'
GROUP BY user_id, user_role, DATE(timestamp)
ORDER BY off_hours_operations DESC;

-- 8. Anomalous data transfers (unusually large data operations)
WITH user_baselines AS (
    SELECT 
        user_id,
        AVG(data_size_bytes) as avg_size,
        STDDEV(data_size_bytes) as stddev_size
    FROM audit_logs
    WHERE data_size_bytes IS NOT NULL
      AND timestamp >= NOW() - INTERVAL '30 days'
    GROUP BY user_id
)
SELECT 
    a.timestamp,
    a.user_id,
    a.operation,
    a.data_size_bytes,
    pg_size_pretty(a.data_size_bytes) as size_human,
    b.avg_size,
    (a.data_size_bytes - b.avg_size) / NULLIF(b.stddev_size, 0) as z_score
FROM audit_logs a
JOIN user_baselines b ON a.user_id = b.user_id
WHERE a.data_size_bytes > b.avg_size + (3 * b.stddev_size)
  AND a.timestamp >= NOW() - INTERVAL '24 hours'
ORDER BY z_score DESC;

-- 9. Multiple failed login attempts from same IP
SELECT 
    ip_address,
    COUNT(DISTINCT user_id) as users_attempted,
    COUNT(*) as failed_attempts,
    ARRAY_AGG(DISTINCT user_id) as user_ids,
    MIN(timestamp) as first_attempt,
    MAX(timestamp) as last_attempt
FROM audit_logs
WHERE operation LIKE '%auth%'
  AND action_result = 'denied'
  AND timestamp >= NOW() - INTERVAL '1 hour'
GROUP BY ip_address
HAVING COUNT(*) >= 5
ORDER BY failed_attempts DESC;

-- 10. Users accessing restricted data
SELECT 
    timestamp,
    user_id,
    user_role,
    operation,
    resource_id,
    action_result,
    policy_decision_reason
FROM audit_logs
WHERE data_classification = 'restricted'
  AND timestamp >= NOW() - INTERVAL '7 days'
ORDER BY timestamp DESC;

-- ============================================================================
-- MEM0-SPECIFIC QUERIES
-- ============================================================================

-- 11. Mem0 operation performance analysis
SELECT 
    mem0_operation,
    COUNT(*) as operation_count,
    AVG(mem0_latency_ms) as avg_latency_ms,
    PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY mem0_latency_ms) as p50_latency,
    PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY mem0_latency_ms) as p95_latency,
    PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY mem0_latency_ms) as p99_latency,
    COUNT(*) FILTER (WHERE mem0_response_code >= 400) as error_count
FROM audit_logs
WHERE mem0_operation IS NOT NULL
  AND timestamp >= NOW() - INTERVAL '24 hours'
GROUP BY mem0_operation
ORDER BY operation_count DESC;

-- 12. Mem0 error rate by operation
SELECT 
    mem0_operation,
    mem0_response_code,
    COUNT(*) as error_count,
    COUNT(*) * 100.0 / SUM(COUNT(*)) OVER (PARTITION BY mem0_operation) as error_percentage,
    MAX(timestamp) as last_error
FROM audit_logs
WHERE mem0_response_code >= 400
  AND timestamp >= NOW() - INTERVAL '7 days'
GROUP BY mem0_operation, mem0_response_code
ORDER BY error_count DESC;

-- 13. Data sent to Mem0 (external data flow)
SELECT 
    DATE(timestamp) as date,
    COUNT(*) as operations,
    COUNT(DISTINCT user_id) as unique_users,
    SUM(data_size_bytes) as total_bytes,
    pg_size_pretty(SUM(data_size_bytes)) as total_size,
    AVG(data_size_bytes) as avg_bytes_per_operation
FROM audit_logs
WHERE mem0_operation IS NOT NULL
  AND timestamp >= NOW() - INTERVAL '30 days'
GROUP BY DATE(timestamp)
ORDER BY date DESC;

-- ============================================================================
-- POLICY EFFECTIVENESS QUERIES
-- ============================================================================

-- 14. Policy decisions by version
SELECT 
    policy_version,
    COUNT(*) as total_evaluations,
    COUNT(*) FILTER (WHERE action_result = 'allowed') as allowed,
    COUNT(*) FILTER (WHERE action_result = 'denied') as denied,
    COUNT(*) FILTER (WHERE action_result = 'error') as errors,
    MIN(timestamp) as first_used,
    MAX(timestamp) as last_used
FROM audit_logs
WHERE policy_version IS NOT NULL
  AND timestamp >= NOW() - INTERVAL '30 days'
GROUP BY policy_version
ORDER BY last_used DESC;

-- 15. Most common denial reasons
SELECT 
    policy_decision_reason,
    COUNT(*) as denial_count,
    COUNT(DISTINCT user_id) as affected_users,
    ARRAY_AGG(DISTINCT operation) as operations
FROM audit_logs
WHERE action_result = 'denied'
  AND policy_decision_reason IS NOT NULL
  AND timestamp >= NOW() - INTERVAL '7 days'
GROUP BY policy_decision_reason
ORDER BY denial_count DESC
LIMIT 10;

-- ============================================================================
-- COMPLIANCE REPORTING
-- ============================================================================

-- 16. SOC 2 Access Report (CC6.1 - Logical Access)
-- Shows all access to sensitive resources
SELECT 
    DATE(timestamp) as date,
    user_id,
    user_role,
    COUNT(*) as access_count,
    COUNT(*) FILTER (WHERE action_result = 'denied') as denied_count,
    COUNT(DISTINCT resource_id) as unique_resources,
    ARRAY_AGG(DISTINCT data_classification) FILTER (WHERE data_classification IS NOT NULL) as data_classes_accessed
FROM audit_logs
WHERE timestamp >= NOW() - INTERVAL '90 days'
GROUP BY DATE(timestamp), user_id, user_role
ORDER BY date DESC, access_count DESC;

-- 17. ISO 27001 Incident Detection (8.15 Logging)
-- Potential security incidents requiring investigation
SELECT 
    timestamp,
    'Multiple Failed Access' as incident_type,
    user_id,
    ip_address,
    operation,
    COUNT(*) as event_count
FROM audit_logs
WHERE action_result = 'denied'
  AND timestamp >= NOW() - INTERVAL '24 hours'
GROUP BY timestamp, user_id, ip_address, operation
HAVING COUNT(*) >= 5

UNION ALL

SELECT 
    timestamp,
    'Privileged Operation' as incident_type,
    user_id,
    ip_address,
    operation,
    1 as event_count
FROM audit_logs
WHERE operation IN ('policy_change', 'user_delete', 'role_change')
  AND timestamp >= NOW() - INTERVAL '24 hours'

ORDER BY timestamp DESC;

-- 18. Data Retention Compliance Report
-- Shows audit log coverage and gaps
SELECT 
    DATE_TRUNC('month', timestamp) as month,
    COUNT(*) as record_count,
    COUNT(DISTINCT user_id) as unique_users,
    COUNT(DISTINCT DATE(timestamp)) as days_covered,
    MIN(timestamp) as earliest_record,
    MAX(timestamp) as latest_record,
    pg_size_pretty(pg_total_relation_size('audit_logs')) as total_table_size
FROM audit_logs
GROUP BY DATE_TRUNC('month', timestamp)
ORDER BY month DESC;

-- ============================================================================
-- PERFORMANCE AND MAINTENANCE QUERIES
-- ============================================================================

-- 19. Table statistics and health
SELECT 
    schemaname,
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as total_size,
    pg_size_pretty(pg_relation_size(schemaname||'.'||tablename)) as table_size,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename) - pg_relation_size(schemaname||'.'||tablename)) as index_size,
    n_live_tup as live_rows,
    n_dead_tup as dead_rows,
    last_vacuum,
    last_autovacuum,
    last_analyze,
    last_autoanalyze
FROM pg_stat_user_tables
WHERE tablename = 'audit_logs';

-- 20. Index usage statistics
SELECT 
    schemaname,
    tablename,
    indexname,
    idx_scan as index_scans,
    idx_tup_read as tuples_read,
    idx_tup_fetch as tuples_fetched,
    pg_size_pretty(pg_relation_size(indexrelid)) as index_size
FROM pg_stat_user_indexes
WHERE tablename = 'audit_logs'
ORDER BY idx_scan DESC;
