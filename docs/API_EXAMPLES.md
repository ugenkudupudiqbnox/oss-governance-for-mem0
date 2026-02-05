# API Usage Examples

Practical examples for using the governed Mem0 API with different roles, tenants, and scenarios.

---

## Table of Contents

- [Header Requirements](#header-requirements)
- [Basic Operations](#basic-operations)
- [Multi-Tenant Operations](#multi-tenant-operations)
- [Rate Limiting](#rate-limiting)
- [Python SDK Examples](#python-sdk-examples)
- [Error Handling](#error-handling)
- [Audit Trail Queries](#audit-trail-queries)

---

## Header Requirements

All API requests **must** include these headers:

| Header | Required | Description | Example |
|--------|----------|-------------|---------|
| `X-User-Id` | Yes | Actor identifier (user/agent/service ID) | `agent-001` |
| `X-User-Role` | Yes | RBAC role (admin, agent-writer, agent-reader, auditor) | `agent-writer` |
| `X-Tenant-Id` | Yes | Tenant context for isolation | `tenant-acme` |
| `Content-Type` | For POST/PUT/PATCH | Must be `application/json` | `application/json` |

Missing headers result in `400 Bad Request`.

---

## Basic Operations

### Create a Memory (Write Permission Required)

**Roles allowed:** `admin`, `agent-writer`

```bash
curl -X POST http://localhost:9000/memories \
  -H "Content-Type: application/json" \
  -H "X-User-Id: agent-001" \
  -H "X-User-Role: agent-writer" \
  -H "X-Tenant-Id: tenant-acme" \
  -d '{
    "messages": [
      {"role": "user", "content": "My favorite color is blue"},
      {"role": "assistant", "content": "I will remember that your favorite color is blue"}
    ],
    "user_id": "user-alice"
  }'
```

**Response (200 OK):**
```json
{
  "id": "mem_abc123",
  "created_at": "2026-02-05T10:30:00Z",
  "user_id": "user-alice"
}
```

---

### Retrieve Memories (Read Permission Required)

**Roles allowed:** `admin`, `agent-writer`, `agent-reader`

```bash
curl http://localhost:9000/memories?user_id=user-alice \
  -H "X-User-Id: agent-001" \
  -H "X-User-Role: agent-reader" \
  -H "X-Tenant-Id: tenant-acme"
```

**Response (200 OK):**
```json
{
  "memories": [
    {
      "id": "mem_abc123",
      "content": "User's favorite color is blue",
      "created_at": "2026-02-05T10:30:00Z"
    }
  ]
}
```

---

### Search Memories

```bash
curl http://localhost:9000/memories/search \
  -H "Content-Type: application/json" \
  -H "X-User-Id: agent-002" \
  -H "X-User-Role: agent-reader" \
  -H "X-Tenant-Id: tenant-acme" \
  -d '{
    "query": "favorite color",
    "user_id": "user-alice"
  }'
```

---

### Delete a Memory (Delete Permission Required)

**Roles allowed:** `admin` only

```bash
curl -X DELETE http://localhost:9000/memories/mem_abc123 \
  -H "X-User-Id: admin-001" \
  -H "X-User-Role: admin" \
  -H "X-Tenant-Id: tenant-acme"
```

**Response (204 No Content)**

---

## Multi-Tenant Operations

### Tenant Isolation (Automatic)

Tenants are automatically isolated. Users can only access resources within their own tenant.

**Tenant A creates a memory:**
```bash
curl -X POST http://localhost:9000/memories \
  -H "Content-Type: application/json" \
  -H "X-User-Id: agent-acme-1" \
  -H "X-User-Role: agent-writer" \
  -H "X-Tenant-Id: tenant-acme" \
  -d '{
    "messages": [{"role": "user", "content": "ACME Corp secret data"}],
    "user_id": "user-acme-123"
  }'
```

**Tenant B tries to access Tenant A's memory:**
```bash
curl http://localhost:9000/memories?user_id=user-acme-123 \
  -H "X-User-Id: agent-globex-1" \
  -H "X-User-Role: agent-reader" \
  -H "X-Tenant-Id: tenant-globex"
```

**Response (403 Forbidden):**
```json
{
  "detail": "Access denied by policy"
}
```

**Why?** OPA policy blocks cross-tenant access. The `resource_tenant` would be `tenant-acme` but the requesting `tenant` is `tenant-globex`.

---

### Creating Memories for Multiple Tenants

Each tenant maintains separate memory spaces:

```bash
# Tenant ACME
curl -X POST http://localhost:9000/memories \
  -H "Content-Type: application/json" \
  -H "X-User-Id: agent-acme" \
  -H "X-User-Role: agent-writer" \
  -H "X-Tenant-Id: tenant-acme" \
  -d '{"messages": [{"role": "user", "content": "ACME data"}], "user_id": "alice"}'

# Tenant Globex
curl -X POST http://localhost:9000/memories \
  -H "Content-Type: application/json" \
  -H "X-User-Id: agent-globex" \
  -H "X-User-Role: agent-writer" \
  -H "X-Tenant-Id: tenant-globex" \
  -d '{"messages": [{"role": "user", "content": "Globex data"}], "user_id": "bob"}'
```

Both succeed, but memories are isolated by tenant.

---

## Rate Limiting

### Standard Rate Limits

- **Non-admin roles:** 100 requests per 60 seconds
- **Admin role:** 500 requests per 60 seconds

Rate limits are per `tenant_id:actor_id` pair.

### Triggering Rate Limit

```bash
# Send 101 requests rapidly as agent-writer
for i in {1..101}; do
  curl -X POST http://localhost:9000/memories \
    -H "Content-Type: application/json" \
    -H "X-User-Id: agent-001" \
    -H "X-User-Role: agent-writer" \
    -H "X-Tenant-Id: tenant-acme" \
    -d '{"messages": [{"role": "user", "content": "Test"}], "user_id": "user-1"}'
done
```

**Response on 101st request (429 Too Many Requests):**
```json
{
  "detail": "Rate limit exceeded"
}
```

**Response headers:**
```
Retry-After: 45
```

This indicates you must wait 45 seconds before retrying.

### Admin Higher Rate Limit

Admins have 5x higher limits:

```bash
curl -X POST http://localhost:9000/memories \
  -H "Content-Type: application/json" \
  -H "X-User-Id: admin-001" \
  -H "X-User-Role: admin" \
  -H "X-Tenant-Id: tenant-acme" \
  -d '{"messages": [{"role": "user", "content": "Admin action"}], "user_id": "user-1"}'
```

Rate limit: 500 requests per 60 seconds.

---

## Python SDK Examples

### Basic Memory Creation

```python
import requests

GATEWAY_URL = "http://localhost:9000"

def create_memory(user_id, content, actor_id, tenant_id):
    """Create a memory through the governed gateway."""
    response = requests.post(
        f"{GATEWAY_URL}/memories",
        headers={
            "Content-Type": "application/json",
            "X-User-Id": actor_id,
            "X-User-Role": "agent-writer",
            "X-Tenant-Id": tenant_id,
        },
        json={
            "messages": [
                {"role": "user", "content": content}
            ],
            "user_id": user_id,
        },
    )
    response.raise_for_status()
    return response.json()

# Usage
memory = create_memory(
    user_id="user-alice",
    content="My favorite programming language is Python",
    actor_id="agent-001",
    tenant_id="tenant-acme"
)
print(f"Created memory: {memory['id']}")
```

---

### Retrieve Memories with Error Handling

```python
import requests
from typing import Optional

def get_memories(user_id, actor_id, tenant_id, role="agent-reader"):
    """Retrieve memories with proper error handling."""
    try:
        response = requests.get(
            f"{GATEWAY_URL}/memories",
            headers={
                "X-User-Id": actor_id,
                "X-User-Role": role,
                "X-Tenant-Id": tenant_id,
            },
            params={"user_id": user_id},
        )
        response.raise_for_status()
        return response.json()

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 403:
            print(f"Access denied: {e.response.json()}")
        elif e.response.status_code == 429:
            retry_after = e.response.headers.get("Retry-After")
            print(f"Rate limited. Retry after {retry_after} seconds")
        else:
            print(f"HTTP error: {e}")
        return None

# Usage
memories = get_memories(
    user_id="user-alice",
    actor_id="agent-002",
    tenant_id="tenant-acme"
)
if memories:
    print(f"Found {len(memories['memories'])} memories")
```

---

### Multi-Tenant Client Class

```python
import requests
from typing import List, Dict, Optional

class GovernedMem0Client:
    """Client for governed Mem0 API with multi-tenant support."""

    def __init__(self, gateway_url: str, actor_id: str, tenant_id: str, role: str):
        self.gateway_url = gateway_url
        self.actor_id = actor_id
        self.tenant_id = tenant_id
        self.role = role

    def _headers(self, content_type: Optional[str] = None) -> Dict[str, str]:
        """Build request headers."""
        headers = {
            "X-User-Id": self.actor_id,
            "X-User-Role": self.role,
            "X-Tenant-Id": self.tenant_id,
        }
        if content_type:
            headers["Content-Type"] = content_type
        return headers

    def add_memory(self, user_id: str, messages: List[Dict]) -> Dict:
        """Add a new memory."""
        response = requests.post(
            f"{self.gateway_url}/memories",
            headers=self._headers("application/json"),
            json={"messages": messages, "user_id": user_id},
        )
        response.raise_for_status()
        return response.json()

    def get_memories(self, user_id: str) -> List[Dict]:
        """Retrieve all memories for a user."""
        response = requests.get(
            f"{self.gateway_url}/memories",
            headers=self._headers(),
            params={"user_id": user_id},
        )
        response.raise_for_status()
        return response.json().get("memories", [])

    def search_memories(self, query: str, user_id: str) -> List[Dict]:
        """Search memories by query."""
        response = requests.post(
            f"{self.gateway_url}/memories/search",
            headers=self._headers("application/json"),
            json={"query": query, "user_id": user_id},
        )
        response.raise_for_status()
        return response.json().get("results", [])

# Usage - Tenant ACME
acme_client = GovernedMem0Client(
    gateway_url="http://localhost:9000",
    actor_id="agent-acme-1",
    tenant_id="tenant-acme",
    role="agent-writer"
)

acme_client.add_memory(
    user_id="alice",
    messages=[{"role": "user", "content": "I work at ACME Corp"}]
)

# Usage - Tenant Globex (isolated)
globex_client = GovernedMem0Client(
    gateway_url="http://localhost:9000",
    actor_id="agent-globex-1",
    tenant_id="tenant-globex",
    role="agent-writer"
)

globex_client.add_memory(
    user_id="bob",
    messages=[{"role": "user", "content": "I work at Globex Inc"}]
)
```

---

## Error Handling

### Common Error Codes

| Status | Meaning | Cause | Solution |
|--------|---------|-------|----------|
| **400** | Bad Request | Missing headers, invalid JSON, path traversal | Check required headers and JSON format |
| **403** | Forbidden | OPA policy denied request | Check role permissions and tenant isolation |
| **429** | Too Many Requests | Rate limit exceeded | Wait for `Retry-After` seconds, or use admin role |
| **503** | Service Unavailable | Mem0 backend not ready | Wait for services to start, check `docker compose ps` |

### Example: Handling All Error Cases

```python
import requests
import time

def robust_add_memory(user_id, content, actor_id, tenant_id, role="agent-writer"):
    """Add memory with comprehensive error handling."""
    max_retries = 3

    for attempt in range(max_retries):
        try:
            response = requests.post(
                "http://localhost:9000/memories",
                headers={
                    "Content-Type": "application/json",
                    "X-User-Id": actor_id,
                    "X-User-Role": role,
                    "X-Tenant-Id": tenant_id,
                },
                json={
                    "messages": [{"role": "user", "content": content}],
                    "user_id": user_id,
                },
                timeout=10,
            )
            response.raise_for_status()
            return response.json()

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 400:
                print(f"Bad request: {e.response.json()}")
                return None  # Don't retry

            elif e.response.status_code == 403:
                print(f"Access denied: {e.response.json()}")
                return None  # Don't retry

            elif e.response.status_code == 429:
                retry_after = int(e.response.headers.get("Retry-After", 60))
                print(f"Rate limited. Waiting {retry_after}s...")
                time.sleep(retry_after)
                continue  # Retry

            elif e.response.status_code == 503:
                print(f"Service unavailable. Retrying in 5s...")
                time.sleep(5)
                continue  # Retry

            else:
                print(f"Unexpected error: {e}")
                return None

        except requests.exceptions.Timeout:
            print(f"Request timeout. Retrying ({attempt + 1}/{max_retries})...")
            time.sleep(2)
            continue

        except requests.exceptions.RequestException as e:
            print(f"Network error: {e}")
            return None

    print(f"Failed after {max_retries} attempts")
    return None
```

---

## Audit Trail Queries

### Query Recent Audit Events via SQL

```bash
docker exec gov_mem0_audit_db psql -U audit -d audit -c \
  "SELECT timestamp, actor_id, actor_role, tenant_id, action, resource, decision
   FROM mem0_audit_log
   WHERE timestamp > NOW() - INTERVAL '1 hour'
   ORDER BY timestamp DESC
   LIMIT 20;"
```

### Find All Denied Requests

```bash
docker exec gov_mem0_audit_db psql -U audit -d audit -c \
  "SELECT timestamp, actor_id, actor_role, tenant_id, action, resource
   FROM mem0_audit_log
   WHERE decision = 'deny'
   ORDER BY timestamp DESC;"
```

### Count Requests by Tenant

```bash
docker exec gov_mem0_audit_db psql -U audit -d audit -c \
  "SELECT tenant_id, decision, COUNT(*) as count
   FROM mem0_audit_log
   GROUP BY tenant_id, decision
   ORDER BY count DESC;"
```

### Find Rate Limited Users

```bash
docker exec gov_mem0_audit_db psql -U audit -d audit -c \
  "SELECT actor_id, tenant_id, COUNT(*) as rate_limit_hits
   FROM mem0_audit_log
   WHERE decision = 'rate_limited'
   GROUP BY actor_id, tenant_id
   ORDER BY rate_limit_hits DESC;"
```

---

## Next Steps

- **[Common Scenarios](./COMMON_SCENARIOS.md)** - Multi-tenant setup, custom roles, production config
- **[Troubleshooting](./TROUBLESHOOTING.md)** - Debug common issues
- **[Quick Start](./QUICKSTART.md)** - Get started from scratch
- **[Architecture Overview](../README.md)** - Understand the system design

---

**Need help?** [Open an issue](https://github.com/your-org/oss-governance-for-mem0/issues)
