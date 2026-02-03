# Database Schemas

This directory contains database schemas for the Governance Pack for Mem0.

## Available Schemas

- [Audit Log Schema](./audit_log_schema.sql) - PostgreSQL schema for comprehensive audit logging

## Overview

### Audit Log Schema

The audit log schema provides:

- **Immutable logging**: Append-only design with constraints
- **Comprehensive tracking**: User, operation, timestamp, outcome, and context
- **Query performance**: Indexed for common audit queries
- **Compliance ready**: Designed for SOC 2 and ISO 27001 requirements
- **Tamper evidence**: Optional cryptographic signatures for log integrity

### Design Principles

1. **Append-Only**: No updates or deletes allowed on audit records
2. **Complete Context**: Captures who, what, when, where, why, and outcome
3. **Searchable**: Indexed for efficient audit queries
4. **Scalable**: Partitioning support for large deployments
5. **Standards-Compliant**: Aligns with audit logging best practices

## Quick Start

### Install the Schema

```bash
# Connect to your PostgreSQL database
psql -U your_user -d your_database -f audit_log_schema.sql
```

### Verify Installation

```sql
-- Check table was created
\dt audit_logs

-- Check indexes
\di audit_logs*

-- Verify constraints
\d audit_logs
```

## Schema Features

### Audit Log Fields

- `id`: Unique identifier (UUID)
- `timestamp`: When the event occurred (with timezone)
- `user_id`: Identifier of the user performing the action
- `user_role`: Role of the user at time of action
- `operation`: Type of operation (e.g., "mem0_search", "policy_check")
- `resource_type`: Type of resource accessed (e.g., "memory", "user", "policy")
- `resource_id`: Specific resource identifier
- `action_result`: Outcome ("allowed", "denied", "error")
- `ip_address`: Source IP address of the request
- `user_agent`: User agent string (for API calls)
- `request_id`: Correlation ID for tracing related operations
- `data_classification`: Sensitivity level ("public", "internal", "confidential", "restricted")
- `data_size_bytes`: Size of data in the operation
- `details`: JSON field for additional context
- `signature`: Optional cryptographic signature for tamper detection

### Performance Considerations

- Indexes on frequently queried columns (user_id, timestamp, operation)
- Consider partitioning by timestamp for large-scale deployments
- Archival strategy recommended after 90 days (move to cold storage)

### Compliance Features

- Immutable by design (use triggers to enforce if needed)
- Retention policies configurable
- WORM (Write Once Read Many) compatible
- Cryptographic integrity optional

## Common Queries

See [query_examples.sql](./query_examples.sql) for common audit queries including:

- Access patterns by user
- Failed access attempts
- Privileged operations
- Data transfer volume
- Compliance reports

## Backup and Retention

### Recommended Practices

1. **Daily backups**: Automated daily backup of audit logs
2. **Retention period**: Minimum 7 years for compliance
3. **Archival**: Move logs older than 90 days to cold storage
4. **Immutability**: Use WORM storage or blockchain for critical audits
5. **Encryption**: Encrypt backups at rest and in transit

### Sample Backup Script

```bash
#!/bin/bash
# Backup audit logs daily
DATE=$(date +%Y%m%d)
pg_dump -U audit_user -t audit_logs your_database | \
  gzip > /backups/audit_logs_$DATE.sql.gz

# Verify backup
gunzip -t /backups/audit_logs_$DATE.sql.gz
```

## Security Considerations

1. **Least Privilege**: Application should have INSERT-only access to audit_logs
2. **Separate Account**: Use dedicated database account for audit logging
3. **Network Security**: Restrict database access to application servers only
4. **Monitoring**: Alert on unusual patterns (e.g., high volume of denies)
5. **Integrity**: Consider cryptographic signatures for high-security environments

## Scaling

For high-volume environments (>1M events/day):

1. **Partitioning**: Partition table by month or week
2. **Replication**: Use read replicas for audit queries
3. **Time-series DB**: Consider migrating to TimescaleDB for better performance
4. **Archival**: Automated archival of old data to object storage

## Integration

### Application Code

```python
# Example: Python with psycopg2
import psycopg2
import uuid
from datetime import datetime

def log_audit_event(conn, user_id, operation, resource_id, result, details):
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO audit_logs (
            id, timestamp, user_id, operation, 
            resource_id, action_result, details
        ) VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, (
        str(uuid.uuid4()),
        datetime.utcnow(),
        user_id,
        operation,
        resource_id,
        result,
        details
    ))
    conn.commit()
```

### With ORM (SQLAlchemy)

```python
from sqlalchemy import create_engine, Column, String, DateTime, JSON
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime
import uuid

Base = declarative_base()

class AuditLog(Base):
    __tablename__ = 'audit_logs'
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(DateTime, default=datetime.utcnow)
    user_id = Column(String, nullable=False)
    operation = Column(String, nullable=False)
    resource_id = Column(String)
    action_result = Column(String, nullable=False)
    details = Column(JSON)
```

## Troubleshooting

### High Insert Volume

If experiencing performance issues:

```sql
-- Check table size
SELECT pg_size_pretty(pg_total_relation_size('audit_logs'));

-- Check index usage
SELECT indexrelname, idx_scan, idx_tup_read, idx_tup_fetch
FROM pg_stat_user_indexes
WHERE schemaname = 'public' AND relname = 'audit_logs';

-- Consider table partitioning
```

### Storage Growth

Monitor and manage storage:

```sql
-- Records by month
SELECT 
    DATE_TRUNC('month', timestamp) as month,
    COUNT(*) as records,
    pg_size_pretty(SUM(pg_column_size(details))) as json_size
FROM audit_logs
GROUP BY month
ORDER BY month DESC;
```

## Migration and Upgrades

When schema changes are needed:

1. Test changes in non-production first
2. Use transactions for schema modifications
3. Keep audit logs during migration (never truncate)
4. Update application code before schema changes
5. Document all schema versions

## Support

For questions or issues with the audit log schema:

- Check [Common Queries](./query_examples.sql)
- Review [Compliance Mappings](../compliance/)
- Open a GitHub issue for bugs or feature requests
