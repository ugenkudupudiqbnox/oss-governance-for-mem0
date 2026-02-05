# Common Scenarios

Practical guides for common use cases and configurations.

---

## Table of Contents

- [Multi-Tenant Setup](#multi-tenant-setup)
- [Custom RBAC Roles](#custom-rbac-roles)
- [Production Rate Limiting](#production-rate-limiting)
- [Integrating with Existing Mem0](#integrating-with-existing-mem0)
- [Compliance Audit Workflows](#compliance-audit-workflows)
- [High Availability Setup](#high-availability-setup)
- [Custom Policy Development](#custom-policy-development)

---

## Multi-Tenant Setup

### Scenario: SaaS Platform with Multiple Customers

You're building a SaaS platform where each customer (tenant) needs isolated AI memory.

**Requirements:**
- Tenant A cannot access Tenant B's data
- Each tenant has multiple users/agents
- Audit trail per tenant

**Implementation:**

#### 1. Define Tenant Structure

```
Tenant: acme-corp
  ├── Users: alice, bob
  └── Agents: agent-acme-1, agent-acme-2

Tenant: globex-inc
  ├── Users: charlie, diana
  └── Agents: agent-globex-1
```

#### 2. Create Memories for Each Tenant

```bash
# ACME Corp - Tenant A
curl -X POST http://localhost:9000/memories \
  -H "Content-Type: application/json" \
  -H "X-User-Id: agent-acme-1" \
  -H "X-User-Role: agent-writer" \
  -H "X-Tenant-Id: acme-corp" \
  -d '{
    "messages": [{"role": "user", "content": "ACME confidential data"}],
    "user_id": "alice"
  }'

# Globex Inc - Tenant B
curl -X POST http://localhost:9000/memories \
  -H "Content-Type: application/json" \
  -H "X-User-Id: agent-globex-1" \
  -H "X-User-Role: agent-writer" \
  -H "X-Tenant-Id: globex-inc" \
  -d '{
    "messages": [{"role": "user", "content": "Globex confidential data"}],
    "user_id": "charlie"
  }'
```

#### 3. Verify Isolation

```bash
# Globex agent tries to read ACME data - DENIED
curl http://localhost:9000/memories?user_id=alice \
  -H "X-User-Id: agent-globex-1" \
  -H "X-User-Role: agent-reader" \
  -H "X-Tenant-Id: globex-inc"

# Response: 403 Forbidden
# Reason: resource belongs to acme-corp, requester is globex-inc
```

#### 4. Audit Per Tenant

```bash
# View all ACME Corp activity
docker exec gov_mem0_audit_db psql -U audit -d audit -c \
  "SELECT timestamp, actor_id, action, decision
   FROM mem0_audit_log
   WHERE tenant_id = 'acme-corp'
   ORDER BY timestamp DESC
   LIMIT 10;"

# View all Globex Inc activity
docker exec gov_mem0_audit_db psql -U audit -d audit -c \
  "SELECT timestamp, actor_id, action, decision
   FROM mem0_audit_log
   WHERE tenant_id = 'globex-inc'
   ORDER BY timestamp DESC
   LIMIT 10;"
```

#### 5. Python Client for Multi-Tenant SaaS

```python
from typing import Dict, List
import requests

class TenantIsolatedMemoryClient:
    """Multi-tenant memory client with automatic isolation."""

    def __init__(self, gateway_url: str):
        self.gateway_url = gateway_url

    def create_tenant_context(self, tenant_id: str, actor_id: str, role: str):
        """Create a tenant-scoped context."""
        return TenantContext(self.gateway_url, tenant_id, actor_id, role)


class TenantContext:
    """Tenant-scoped operations."""

    def __init__(self, gateway_url: str, tenant_id: str, actor_id: str, role: str):
        self.gateway_url = gateway_url
        self.tenant_id = tenant_id
        self.actor_id = actor_id
        self.role = role

    def _headers(self) -> Dict[str, str]:
        return {
            "X-User-Id": self.actor_id,
            "X-User-Role": self.role,
            "X-Tenant-Id": self.tenant_id,
            "Content-Type": "application/json",
        }

    def add_memory(self, user_id: str, content: str) -> Dict:
        """Add memory within this tenant's context."""
        response = requests.post(
            f"{self.gateway_url}/memories",
            headers=self._headers(),
            json={
                "messages": [{"role": "user", "content": content}],
                "user_id": user_id,
            },
        )
        response.raise_for_status()
        return response.json()

    def get_memories(self, user_id: str) -> List[Dict]:
        """Get memories for user within this tenant."""
        response = requests.get(
            f"{self.gateway_url}/memories",
            headers=self._headers(),
            params={"user_id": user_id},
        )
        response.raise_for_status()
        return response.json().get("memories", [])


# Usage
client = TenantIsolatedMemoryClient("http://localhost:9000")

# Tenant ACME
acme = client.create_tenant_context(
    tenant_id="acme-corp",
    actor_id="agent-acme-1",
    role="agent-writer"
)
acme.add_memory("alice", "ACME project Alpha details")

# Tenant Globex (isolated from ACME)
globex = client.create_tenant_context(
    tenant_id="globex-inc",
    actor_id="agent-globex-1",
    role="agent-writer"
)
globex.add_memory("charlie", "Globex project Beta details")
```

---

## Custom RBAC Roles

### Scenario: Create a "Supervisor" Role

You need a role that can read and write, but not delete, and has higher rate limits than regular agents.

**Requirements:**
- Read and write permissions
- No delete permission
- Rate limit: 300 requests/minute
- Tenant-isolated

#### 1. Define Policy in OPA

Create `policies/supervisor_role.rego`:

```rego
package mem0.authz

# Supervisor role permissions
supervisor_permissions := {
    "read": true,
    "write": true,
    "delete": false,
}

# Allow supervisor role with tenant isolation
allow {
    input.roles[_] == "supervisor"
    action := supervisor_permissions[input.action]
    action == true
    input.tenant == input.resource_tenant
}
```

#### 2. Update Gateway Rate Limiting

Edit `gateway/middleware/main.py`:

```python
def check_rate_limit(tenant_id: str, actor_id: str, actor_role: str) -> tuple[bool, int]:
    """Sliding window rate limiter with role-based limits."""
    now = time.time()
    key = f"{tenant_id}:{actor_id}"
    window = _rate_limit_buckets[key]

    cutoff = now - RATE_LIMIT_WINDOW_SECONDS
    while window and window[0] <= cutoff:
        window.popleft()

    # Role-based limits
    if actor_role == "admin":
        limit = RATE_LIMIT_ADMIN_REQUESTS
    elif actor_role == "supervisor":
        limit = 300  # Custom limit for supervisor
    else:
        limit = RATE_LIMIT_REQUESTS

    if len(window) >= limit:
        retry_after = int(window[0] + RATE_LIMIT_WINDOW_SECONDS - now) + 1
        return False, max(retry_after, 1)

    window.append(now)
    return True, 0
```

#### 3. Rebuild Gateway

```bash
cd docker
docker compose build gateway
docker compose up -d gateway
```

#### 4. Test Supervisor Role

```bash
# Supervisor can read
curl http://localhost:9000/memories \
  -H "X-User-Id: supervisor-001" \
  -H "X-User-Role: supervisor" \
  -H "X-Tenant-Id: tenant-acme"
# ✅ Allowed

# Supervisor can write
curl -X POST http://localhost:9000/memories \
  -H "Content-Type: application/json" \
  -H "X-User-Id: supervisor-001" \
  -H "X-User-Role: supervisor" \
  -H "X-Tenant-Id: tenant-acme" \
  -d '{"messages": [{"role": "user", "content": "Test"}], "user_id": "user-1"}'
# ✅ Allowed

# Supervisor cannot delete
curl -X DELETE http://localhost:9000/memories/mem_123 \
  -H "X-User-Id: supervisor-001" \
  -H "X-User-Role: supervisor" \
  -H "X-Tenant-Id: tenant-acme"
# ❌ Denied (403 Forbidden)
```

#### 5. Add Policy Tests

Create `policies/tests/supervisor_test.rego`:

```rego
package mem0.authz

test_supervisor_can_read {
    allow with input as {
        "action": "read",
        "roles": ["supervisor"],
        "tenant": "tenant-a",
        "resource_tenant": "tenant-a"
    }
}

test_supervisor_can_write {
    allow with input as {
        "action": "write",
        "roles": ["supervisor"],
        "tenant": "tenant-a",
        "resource_tenant": "tenant-a"
    }
}

test_supervisor_cannot_delete {
    not allow with input as {
        "action": "delete",
        "roles": ["supervisor"],
        "tenant": "tenant-a",
        "resource_tenant": "tenant-a"
    }
}

test_supervisor_tenant_isolation {
    not allow with input as {
        "action": "read",
        "roles": ["supervisor"],
        "tenant": "tenant-a",
        "resource_tenant": "tenant-b"
    }
}
```

Test:
```bash
docker exec gov_mem0_opa opa test /policies -v
```

---

## Production Rate Limiting

### Scenario: Redis-Backed Distributed Rate Limiting

For production with multiple gateway instances, use Redis instead of in-memory rate limiting.

#### 1. Add Redis to Docker Compose

Edit `docker/docker-compose.yml`:

```yaml
services:
  redis:
    image: redis:7-alpine
    container_name: gov_mem0_redis
    ports:
      - "9007:6379"
    restart: unless-stopped

  gateway:
    depends_on:
      - redis
    environment:
      REDIS_URL: redis://redis:6379/0
```

#### 2. Update Gateway Dependencies

Add to `gateway/middleware/requirements.txt`:
```
redis>=5.0.0
```

#### 3. Implement Redis Rate Limiter

Update `gateway/middleware/main.py`:

```python
import redis
import time

# Redis connection
redis_url = os.getenv("REDIS_URL", None)
if redis_url:
    redis_client = redis.from_url(redis_url, decode_responses=True)
else:
    redis_client = None

def check_rate_limit_redis(tenant_id: str, actor_id: str, actor_role: str) -> tuple[bool, int]:
    """Redis-backed sliding window rate limiter."""
    if not redis_client:
        # Fallback to in-memory if Redis not configured
        return check_rate_limit(tenant_id, actor_id, actor_role)

    now = time.time()
    key = f"ratelimit:{tenant_id}:{actor_id}"
    window = RATE_LIMIT_WINDOW_SECONDS

    limit = RATE_LIMIT_ADMIN_REQUESTS if actor_role == "admin" else RATE_LIMIT_REQUESTS

    # Remove expired entries
    redis_client.zremrangebyscore(key, 0, now - window)

    # Count current requests in window
    count = redis_client.zcard(key)

    if count >= limit:
        # Get oldest timestamp to calculate retry_after
        oldest = redis_client.zrange(key, 0, 0, withscores=True)
        if oldest:
            oldest_time = oldest[0][1]
            retry_after = int(oldest_time + window - now) + 1
            return False, max(retry_after, 1)

    # Add current request
    redis_client.zadd(key, {str(now): now})
    redis_client.expire(key, window)

    return True, 0
```

Update the route handler to use Redis version:
```python
@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def proxy(request: Request, path: str):
    # ... validation ...

    # Use Redis rate limiter if available
    if redis_client:
        allowed, retry_after = check_rate_limit_redis(tenant_id, actor_id, actor_role)
    else:
        allowed, retry_after = check_rate_limit(tenant_id, actor_id, actor_role)

    # ... rest of handler ...
```

#### 4. Deploy and Test

```bash
cd docker
docker compose up -d redis
docker compose build gateway
docker compose up -d gateway

# Verify Redis connection
docker exec gov_mem0_gateway python -c "
import redis, os
r = redis.from_url(os.getenv('REDIS_URL'))
r.ping()
print('Redis connected')
"
```

---

## Integrating with Existing Mem0

### Scenario: Add Governance to Running Mem0 Instance

You already have Mem0 running and want to add governance without downtime.

#### 1. Current Architecture

```
Clients → Mem0 (port 8000)
```

#### 2. Target Architecture

```
Clients → Gateway (port 9000) → OPA → Mem0 (port 8000)
```

#### 3. Migration Steps

**Step 1: Deploy governance stack WITHOUT gateway**

Edit `docker/docker-compose.yml` and comment out gateway:
```yaml
services:
  # gateway:  # Comment out for now
  #   ...

  opa:
    # ... keep OPA
  audit-db:
    # ... keep audit DB
```

Start:
```bash
cd docker
docker compose up -d
```

**Step 2: Test OPA policies**

```bash
docker exec gov_mem0_opa opa test /policies -v
```

**Step 3: Configure gateway to point to existing Mem0**

Edit `docker/docker-compose.yml`:
```yaml
gateway:
  environment:
    MEM0_URL: http://your-existing-mem0-host:8000  # Point to existing Mem0
```

**Step 4: Deploy gateway on different port (no downtime)**

```yaml
gateway:
  ports:
    - "9000:8080"  # New governed endpoint
```

Start gateway:
```bash
docker compose up -d gateway
```

**Step 5: Test governed endpoint**

```bash
# Old endpoint (ungoverned) - still works
curl http://localhost:8000/memories

# New endpoint (governed)
curl http://localhost:9000/memories \
  -H "X-User-Id: test" \
  -H "X-User-Role: admin" \
  -H "X-Tenant-Id: default"
```

**Step 6: Migrate clients gradually**

Update client apps to use `http://localhost:9000` instead of `http://localhost:8000`.

**Step 7: Block direct Mem0 access (optional)**

After all clients migrated, restrict Mem0 to only accept connections from gateway:

```yaml
mem0:
  networks:
    - internal  # Remove from public network
```

---

## Compliance Audit Workflows

### Scenario: Monthly Access Review for SOC 2

Generate reports for auditors showing who accessed what.

#### 1. All Access by Tenant (Last 30 Days)

```bash
docker exec gov_mem0_audit_db psql -U audit -d audit -c \
  "SELECT
     tenant_id,
     actor_role,
     COUNT(*) as total_requests,
     SUM(CASE WHEN decision = 'allow' THEN 1 ELSE 0 END) as allowed,
     SUM(CASE WHEN decision = 'deny' THEN 1 ELSE 0 END) as denied
   FROM mem0_audit_log
   WHERE timestamp > NOW() - INTERVAL '30 days'
   GROUP BY tenant_id, actor_role
   ORDER BY tenant_id, total_requests DESC;" \
  --csv > access_review_$(date +%Y-%m).csv
```

#### 2. Failed Access Attempts (Security Review)

```bash
docker exec gov_mem0_audit_db psql -U audit -d audit -c \
  "SELECT
     timestamp,
     actor_id,
     actor_role,
     tenant_id,
     action,
     resource,
     decision
   FROM mem0_audit_log
   WHERE decision IN ('deny', 'invalid_request')
     AND timestamp > NOW() - INTERVAL '30 days'
   ORDER BY timestamp DESC;" \
  --csv > failed_access_$(date +%Y-%m).csv
```

#### 3. High-Privilege Activity (Admin Actions)

```bash
docker exec gov_mem0_audit_db psql -U audit -d audit -c \
  "SELECT
     timestamp,
     actor_id,
     tenant_id,
     action,
     resource
   FROM mem0_audit_log
   WHERE actor_role = 'admin'
     AND timestamp > NOW() - INTERVAL '30 days'
   ORDER BY timestamp DESC;" \
  --csv > admin_activity_$(date +%Y-%m).csv
```

#### 4. Automated Monthly Report Script

Create `scripts/monthly_audit_report.sh`:

```bash
#!/bin/bash
set -e

YEAR_MONTH=$(date +%Y-%m)
REPORT_DIR="audit_reports/$YEAR_MONTH"
mkdir -p "$REPORT_DIR"

echo "Generating audit reports for $YEAR_MONTH..."

# Access summary
docker exec gov_mem0_audit_db psql -U audit -d audit -c \
  "SELECT tenant_id, actor_role, COUNT(*) as requests,
   SUM(CASE WHEN decision='allow' THEN 1 ELSE 0 END) as allowed,
   SUM(CASE WHEN decision='deny' THEN 1 ELSE 0 END) as denied
   FROM mem0_audit_log
   WHERE timestamp >= date_trunc('month', CURRENT_DATE)
   GROUP BY tenant_id, actor_role;" \
  --csv > "$REPORT_DIR/access_summary.csv"

# Failed attempts
docker exec gov_mem0_audit_db psql -U audit -d audit -c \
  "SELECT * FROM mem0_audit_log
   WHERE decision IN ('deny', 'invalid_request')
     AND timestamp >= date_trunc('month', CURRENT_DATE)
   ORDER BY timestamp DESC;" \
  --csv > "$REPORT_DIR/failed_access.csv"

# Admin activity
docker exec gov_mem0_audit_db psql -U audit -d audit -c \
  "SELECT * FROM mem0_audit_log
   WHERE actor_role = 'admin'
     AND timestamp >= date_trunc('month', CURRENT_DATE)
   ORDER BY timestamp DESC;" \
  --csv > "$REPORT_DIR/admin_activity.csv"

echo "Reports saved to $REPORT_DIR/"
ls -lh "$REPORT_DIR/"
```

Run monthly:
```bash
chmod +x scripts/monthly_audit_report.sh
./scripts/monthly_audit_report.sh
```

---

## High Availability Setup

### Scenario: Production Deployment with HA

Run multiple gateway instances behind a load balancer.

**Requirements:**
- 3+ gateway instances
- Shared Redis for rate limiting
- PostgreSQL with replication
- Load balancer

#### Architecture

```
                    ┌─────────────┐
        ┌──────────>│  Gateway 1  │──────┐
        │           └─────────────┘      │
        │                                │
  Load  │           ┌─────────────┐      │      ┌──────┐
Balancer├──────────>│  Gateway 2  │──────┼─────>│ OPA  │
        │           └─────────────┘      │      └──────┘
        │                                │
        │           ┌─────────────┐      │
        └──────────>│  Gateway 3  │──────┘
                    └─────────────┘
                           │
                           ▼
                    ┌─────────────┐
                    │    Redis    │ (Rate limiting)
                    └─────────────┘
                           │
                           ▼
                    ┌─────────────┐
                    │ PostgreSQL  │ (Audit logs)
                    └─────────────┘
```

#### Docker Compose (Production)

```yaml
version: "3.9"

services:
  gateway:
    image: governance-gateway:latest
    deploy:
      replicas: 3  # Multiple instances
    environment:
      REDIS_URL: redis://redis:6379/0
      OPA_URL: http://opa:8181/v1/data/mem0/authz/allow
      DB_HOST: postgres
    depends_on:
      - redis
      - opa
      - postgres

  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes
    volumes:
      - redis_data:/data

  postgres:
    image: pgvector/pgvector:pg15
    environment:
      POSTGRES_DB: audit
      POSTGRES_USER: audit
      POSTGRES_PASSWORD: ${DB_PASSWORD}  # From secrets
    volumes:
      - postgres_data:/var/lib/postgresql/data

  nginx:  # Load balancer
    image: nginx:alpine
    ports:
      - "9000:80"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
    depends_on:
      - gateway

volumes:
  redis_data:
  postgres_data:
```

---

## Custom Policy Development

### Scenario: Time-Based Access Control

Allow write operations only during business hours (9 AM - 5 PM UTC).

#### Create Policy

`policies/time_based_access.rego`:

```rego
package mem0.authz

import future.keywords.if

# Parse current hour from time.now_ns()
current_hour := hour {
    now := time.now_ns()
    [_, time_str] := time.parse_rfc3339_ns(time.format(now))
    hour := time.clock(time_str)[0]
}

# Business hours: 9 AM - 5 PM UTC
is_business_hours {
    current_hour >= 9
    current_hour < 17
}

# Allow writes only during business hours
allow if {
    input.action == "write"
    input.roles[_] == "agent-writer"
    is_business_hours
    input.tenant == input.resource_tenant
}

# Reads allowed anytime
allow if {
    input.action == "read"
    input.roles[_] == "agent-reader"
    input.tenant == input.resource_tenant
}
```

Test outside business hours:
```bash
# At 6 PM UTC, writes are denied
curl -X POST http://localhost:9000/memories \
  -H "X-User-Role: agent-writer" \
  ...
# Response: 403 Forbidden
```

---

## Next Steps

- **[Quick Start](./QUICKSTART.md)** - Get started from scratch
- **[API Examples](./API_EXAMPLES.md)** - More API patterns
- **[Troubleshooting](./TROUBLESHOOTING.md)** - Debug issues
- **[Architecture Docs](../README.md)** - Deep dive into design

---

**Need help with your scenario?** [Open an issue](https://github.com/your-org/oss-governance-for-mem0/issues)
