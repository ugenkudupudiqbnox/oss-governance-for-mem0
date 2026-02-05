# Quick Start Guide

Get the Governance Pack for Mem0 running in under 10 minutes.

---

## Prerequisites

Before you begin, ensure you have:

- **Docker** (20.10+) and **Docker Compose** (2.0+)
- **8GB RAM** available for containers
- **Ports available**: 9000-9006 (or configure alternatives)
- **Git** for cloning the repository

Check your Docker installation:
```bash
docker --version
docker compose version
```

---

## Step 1: Clone the Repository

```bash
git clone https://github.com/your-org/oss-governance-for-mem0.git
cd oss-governance-for-mem0
```

---

## Step 2: Start the Governance Stack

Launch all services with a single command:

```bash
cd docker
docker compose up -d
```

This starts 9 services:
- **Gateway** (9000) - API entry point with governance
- **OPA** (9001) - Policy engine
- **Keycloak** (9002) - Identity and access management
- **Grafana** (9003) - Dashboards
- **Loki** (9004) - Log aggregation
- **Audit DB** (9005) - PostgreSQL audit trail
- **Mem0** (9006) - Memory backend
- Supporting databases (Keycloak DB, Postgres)

Initial startup takes 30-60 seconds. Monitor progress:
```bash
docker compose logs -f
```

Press `Ctrl+C` to stop following logs.

---

## Step 3: Verify Services Are Running

Check that all services are healthy:

```bash
docker compose ps
```

Expected output - all services should show "Up":
```
NAME                   STATUS
gov_mem0_audit_db      Up
gov_mem0_gateway       Up
gov_mem0_grafana       Up
gov_mem0_keycloak      Up
gov_mem0_keycloak_db   Up
gov_mem0_loki          Up
gov_mem0_mem0          Up
gov_mem0_opa           Up
gov_mem0_postgres      Up
```

Test the gateway health endpoint:
```bash
curl http://localhost:9000/health
```

Expected response:
```json
{"status":"healthy"}
```

---

## Step 4: Your First Governed API Call

All requests to Mem0 now flow through the governance gateway with authorization, rate limiting, and audit logging.

### Example: Add a Memory (as Agent Writer)

```bash
curl -X POST http://localhost:9000/memories \
  -H "Content-Type: application/json" \
  -H "X-User-Id: agent-001" \
  -H "X-User-Role: agent-writer" \
  -H "X-Tenant-Id: tenant-acme" \
  -d '{
    "messages": [{"role": "user", "content": "Remember that I prefer dark mode"}],
    "user_id": "user-123"
  }'
```

**What just happened:**
1. Gateway validated your request headers
2. Gateway checked rate limits (100 requests/minute for agent-writer)
3. Gateway called OPA to authorize the request
4. OPA evaluated RBAC policies and approved (agent-writer can write)
5. Gateway proxied to Mem0 backend
6. Gateway logged the "allow" decision to audit database

### Example: Retrieve Memories

```bash
curl http://localhost:9000/memories \
  -H "X-User-Id: agent-001" \
  -H "X-User-Role: agent-reader" \
  -H "X-Tenant-Id: tenant-acme"
```

### Example: Unauthorized Access (Denied)

Try to write with a read-only role:

```bash
curl -X POST http://localhost:9000/memories \
  -H "Content-Type: application/json" \
  -H "X-User-Id: agent-002" \
  -H "X-User-Role: agent-reader" \
  -H "X-Tenant-Id: tenant-acme" \
  -d '{
    "messages": [{"role": "user", "content": "Test"}],
    "user_id": "user-456"
  }'
```

Expected response:
```json
{
  "detail": "Access denied by policy"
}
```

**What happened:** OPA denied the request because `agent-reader` role only has `read` permission, not `write`.

---

## Step 5: View Audit Logs

Every API call is logged to the audit database. View recent audit events:

```bash
docker exec gov_mem0_audit_db psql -U audit -d audit -c \
  "SELECT timestamp, actor_id, actor_role, tenant_id, action, decision
   FROM mem0_audit_log
   ORDER BY timestamp DESC
   LIMIT 10;"
```

Example output:
```
        timestamp        |  actor_id  |  actor_role  |  tenant_id  | action | decision
-------------------------+------------+--------------+-------------+--------+----------
 2026-02-05 10:15:23     | agent-001  | agent-writer | tenant-acme | write  | allow
 2026-02-05 10:15:18     | agent-002  | agent-reader | tenant-acme | write  | deny
 2026-02-05 10:14:55     | agent-001  | agent-reader | tenant-acme | read   | allow
```

---

## Step 6: Explore the Grafana Dashboard

Open Grafana in your browser:
```
http://localhost:9003
```

**Default credentials:**
- Username: `admin`
- Password: `admin` (you'll be prompted to change on first login)

Navigate to **Dashboards** → **Mem0 Audit Trail** to visualize audit events in real-time.

---

## Understanding RBAC Roles

The governance stack includes 4 pre-configured roles:

| Role | Permissions | Use Case |
|------|-------------|----------|
| **admin** | Full access (read/write/delete/audit), higher rate limits (500/min) | System administrators |
| **agent-writer** | Read and write memories, tenant-isolated | AI agents that create memories |
| **agent-reader** | Read-only access, tenant-isolated | AI agents that only retrieve memories |
| **auditor** | Access audit logs only | Compliance and security teams |

Tenant isolation is automatic - users can only access resources in their own tenant.

---

## Next Steps

Now that you have the governance stack running:

1. **[API Usage Examples](./API_EXAMPLES.md)** - Learn common API patterns
2. **[Common Scenarios](./COMMON_SCENARIOS.md)** - Multi-tenant setup, custom roles
3. **[Troubleshooting Guide](./TROUBLESHOOTING.md)** - Solve common issues
4. **[Architecture Overview](../README.md)** - Understand the system design
5. **[Testing Guide](../gateway/middleware/README_TESTS.md)** - Run test suite

---

## Configuration

The governance stack uses environment variables for configuration. Key settings:

### Rate Limiting
```bash
# In docker/docker-compose.yml, gateway service environment:
RATE_LIMIT_REQUESTS=100              # Requests per window (non-admin)
RATE_LIMIT_WINDOW_SECONDS=60         # Window size
RATE_LIMIT_ADMIN_REQUESTS=500        # Admin requests per window
```

### Request Validation
```bash
MAX_BODY_SIZE_BYTES=1048576          # Max request body (1MB default)
```

### Service URLs
```bash
OPA_URL=http://opa:8181/v1/data/mem0/authz/allow
MEM0_URL=http://mem0:8000
DB_HOST=audit-db
```

To customize, edit `docker/docker-compose.yml` and restart:
```bash
docker compose down
docker compose up -d
```

---

## Stopping the Stack

Stop all services:
```bash
docker compose down
```

Stop and remove all data (including audit logs):
```bash
docker compose down -v
```

**Warning:** The `-v` flag deletes all persistent data including audit trails. Only use in development.

---

## Troubleshooting Quick Tips

**Port already in use:**
```bash
# Check what's using port 9000
lsof -i :9000

# Stop the process or change port in docker-compose.yml
```

**Service not starting:**
```bash
# Check logs for specific service
docker compose logs gateway
docker compose logs opa
```

**Gateway returns 503 (Service Unavailable):**
- Mem0 backend may not be ready yet. Wait 30 seconds after startup.
- Check: `curl http://localhost:9006/health`

**OPA policy errors:**
```bash
# Test OPA policies manually
docker exec gov_mem0_opa opa test /policies -v
```

For more detailed troubleshooting, see [TROUBLESHOOTING.md](./TROUBLESHOOTING.md).

---

## Security Notice

⚠️ **This quick start uses development defaults:**
- Default admin passwords (`admin/admin`)
- No TLS/HTTPS
- Permissive network settings
- In-memory rate limiting (single-instance only)

**Do not use in production without hardening.** See production deployment guide (coming soon).

---

## Getting Help

- **Issues**: [GitHub Issues](https://github.com/your-org/oss-governance-for-mem0/issues)
- **Documentation**: [README.md](../README.md)
- **Examples**: [API_EXAMPLES.md](./API_EXAMPLES.md)

---

**You're ready to build governed AI memory systems!** 🚀
