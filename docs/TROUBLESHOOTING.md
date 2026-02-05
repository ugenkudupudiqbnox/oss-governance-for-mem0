# Troubleshooting Guide

Common issues and solutions for the Governance Pack for Mem0.

---

## Table of Contents

- [Quick Diagnostics](#quick-diagnostics)
- [Service Issues](#service-issues)
- [Gateway Errors](#gateway-errors)
- [OPA Policy Errors](#opa-policy-errors)
- [Database Issues](#database-issues)
- [Network & Port Conflicts](#network--port-conflicts)
- [Performance Issues](#performance-issues)
- [Docker Issues](#docker-issues)

---

## Quick Diagnostics

Run these commands first to identify the problem area:

```bash
# 1. Check all services are running
cd docker && docker compose ps

# 2. Check gateway health
curl http://localhost:9000/health

# 3. Check gateway logs
docker compose logs gateway --tail=50

# 4. Check OPA logs
docker compose logs opa --tail=50

# 5. Test OPA policies
docker exec gov_mem0_opa opa test /policies -v

# 6. Check audit database connection
docker exec gov_mem0_audit_db psql -U audit -d audit -c "SELECT COUNT(*) FROM mem0_audit_log;"
```

---

## Service Issues

### Problem: Service Not Starting

**Symptoms:**
```bash
$ docker compose ps
gov_mem0_gateway   Exit 1
```

**Diagnosis:**
```bash
docker compose logs gateway
```

**Common Causes & Solutions:**

1. **Missing environment variables**
   ```
   Error: DB_HOST not set
   ```
   **Solution:** Check `docker/docker-compose.yml` gateway service environment section.

2. **Dependency not ready**
   ```
   Error connecting to OPA: Connection refused
   ```
   **Solution:** OPA may not be ready yet. Wait 10 seconds and restart:
   ```bash
   docker compose restart gateway
   ```

3. **Port already in use**
   ```
   Error: bind: address already in use
   ```
   **Solution:** See [Network & Port Conflicts](#network--port-conflicts).

---

### Problem: Gateway Returns 503 (Service Unavailable)

**Symptoms:**
```bash
$ curl http://localhost:9000/memories
{"detail":"Service temporarily unavailable"}
```

**Diagnosis:**
```bash
# Check if Mem0 backend is running
curl http://localhost:9006/health

# Check gateway logs
docker compose logs gateway --tail=20
```

**Solutions:**

1. **Mem0 not ready yet**
   - Wait 30-60 seconds after `docker compose up -d`
   - Mem0 takes time to initialize

2. **Mem0 crashed**
   ```bash
   docker compose restart mem0
   docker compose logs mem0
   ```

3. **Network connectivity issue**
   ```bash
   # Test from inside gateway container
   docker exec gov_mem0_gateway curl http://mem0:8000/health
   ```

---

### Problem: All Services Exit Immediately After Start

**Symptoms:**
```bash
$ docker compose up -d
$ docker compose ps
# All services show "Exit 0" or "Exit 1"
```

**Diagnosis:**
```bash
docker compose logs
```

**Common Cause:** Insufficient Docker resources (RAM, CPU).

**Solution:**
1. Check Docker resource limits:
   - Docker Desktop: Settings → Resources
   - Minimum: 8GB RAM, 4 CPU cores

2. Stop other Docker containers:
   ```bash
   docker ps -a
   docker stop $(docker ps -q)
   ```

3. Restart with verbose logging:
   ```bash
   docker compose down
   docker compose up
   ```

---

## Gateway Errors

### Problem: 400 Bad Request - Missing Headers

**Error Response:**
```json
{
  "detail": "Missing required header: X-User-Role"
}
```

**Solution:** Include all required headers in every request:
```bash
curl http://localhost:9000/memories \
  -H "X-User-Id: agent-001" \
  -H "X-User-Role: agent-reader" \
  -H "X-Tenant-Id: tenant-acme"
```

Required headers:
- `X-User-Id`
- `X-User-Role`
- `X-Tenant-Id`
- `Content-Type: application/json` (for POST/PUT/PATCH)

---

### Problem: 400 Bad Request - Invalid JSON

**Error Response:**
```json
{
  "detail": "Request body must be valid JSON"
}
```

**Common Causes:**

1. **Malformed JSON:**
   ```bash
   # Wrong: missing quotes
   curl -X POST http://localhost:9000/memories \
     -H "Content-Type: application/json" \
     -d '{user_id: alice}'

   # Correct:
   curl -X POST http://localhost:9000/memories \
     -H "Content-Type: application/json" \
     -d '{"user_id": "alice"}'
   ```

2. **Missing Content-Type header:**
   ```bash
   # Always include for POST/PUT/PATCH:
   -H "Content-Type: application/json"
   ```

3. **Body too large:**
   ```
   Error: Request body exceeds maximum size (1MB)
   ```
   **Solution:** Increase `MAX_BODY_SIZE_BYTES` in gateway environment or split request.

---

### Problem: 403 Forbidden - Access Denied

**Error Response:**
```json
{
  "detail": "Access denied by policy"
}
```

**Diagnosis:**

1. **Check actor role has required permission:**
   ```bash
   # agent-reader cannot write
   curl -X POST http://localhost:9000/memories \
     -H "X-User-Role: agent-reader"  # ❌ Denied

   # agent-writer can write
   curl -X POST http://localhost:9000/memories \
     -H "X-User-Role: agent-writer"  # ✅ Allowed
   ```

2. **Check tenant isolation:**
   ```bash
   # User in tenant-acme cannot access tenant-globex resources
   # This is expected behavior
   ```

3. **Check audit logs to see why denied:**
   ```bash
   docker exec gov_mem0_audit_db psql -U audit -d audit -c \
     "SELECT timestamp, actor_id, actor_role, tenant_id, action, decision
      FROM mem0_audit_log
      WHERE decision = 'deny'
      ORDER BY timestamp DESC
      LIMIT 5;"
   ```

**Solutions:**

| Role | Can Read | Can Write | Can Delete |
|------|----------|-----------|------------|
| admin | ✅ | ✅ | ✅ |
| agent-writer | ✅ | ✅ | ❌ |
| agent-reader | ✅ | ❌ | ❌ |
| auditor | ❌ | ❌ | ❌ |

Use the correct role for your operation.

---

### Problem: 429 Too Many Requests - Rate Limited

**Error Response:**
```json
{
  "detail": "Rate limit exceeded"
}
```

**Response Headers:**
```
Retry-After: 45
```

**Solutions:**

1. **Wait for retry window:**
   - Standard limit: 100 requests/60 seconds
   - Admin limit: 500 requests/60 seconds
   - Wait the number of seconds specified in `Retry-After` header

2. **Use admin role for bulk operations:**
   ```bash
   curl -X POST http://localhost:9000/memories \
     -H "X-User-Role: admin"  # Higher rate limit
   ```

3. **Adjust rate limits (development only):**
   Edit `docker/docker-compose.yml`:
   ```yaml
   gateway:
     environment:
       RATE_LIMIT_REQUESTS: 1000        # Increase from 100
       RATE_LIMIT_WINDOW_SECONDS: 60
   ```
   Then restart:
   ```bash
   docker compose restart gateway
   ```

4. **Implement backoff in code:**
   ```python
   import time
   retry_after = int(response.headers.get("Retry-After", 60))
   time.sleep(retry_after)
   ```

---

## OPA Policy Errors

### Problem: OPA Policy Tests Failing

**Symptoms:**
```bash
$ docker exec gov_mem0_opa opa test /policies -v
FAIL: test_admin_can_read
```

**Diagnosis:**
```bash
# Run tests with verbose output
docker exec gov_mem0_opa opa test /policies -v

# Check policy syntax
docker exec gov_mem0_opa opa check /policies
```

**Solutions:**

1. **Syntax error in policy:**
   ```bash
   # Validate Rego syntax
   docker exec gov_mem0_opa opa check /policies/role_based_access.rego
   ```

2. **Test input doesn't match policy:**
   - Check `policies/tests/role_access_test.rego`
   - Ensure test inputs use correct structure (see CLAUDE.md)

3. **Policy file not mounted:**
   ```bash
   # Verify policies are mounted in container
   docker exec gov_mem0_opa ls -la /policies
   ```

---

### Problem: OPA Returns Unexpected Denials

**Symptoms:**
- Request should be allowed but gets 403
- Audit log shows `decision = 'deny'`

**Diagnosis:**

1. **Test OPA directly:**
   ```bash
   docker exec gov_mem0_opa curl -X POST http://localhost:8181/v1/data/mem0/authz/allow \
     -H "Content-Type: application/json" \
     -d '{
       "input": {
         "action": "read",
         "roles": ["agent-reader"],
         "tenant": "tenant-acme",
         "resource_tenant": "tenant-acme"
       }
     }'
   ```

   Expected response for allowed:
   ```json
   {"result": true}
   ```

2. **Check OPA decision logs:**
   ```bash
   docker compose logs opa --tail=50 | grep "decision"
   ```

**Solutions:**

1. **Verify policy package name:**
   - All policies must use `package mem0.authz`
   - Gateway queries `/v1/data/mem0/authz/allow`

2. **Check default rule:**
   - `policies/deny_by_default.rego` should have `default allow = false`
   - At least one policy must set `allow = true` for request to succeed

---

## Database Issues

### Problem: Cannot Connect to Audit Database

**Symptoms:**
```
Error: could not connect to server: Connection refused
```

**Diagnosis:**
```bash
# Check if database is running
docker compose ps audit-db

# Check database logs
docker compose logs audit-db --tail=20

# Try connecting from host
psql -h localhost -p 9005 -U audit -d audit
# Password: audit
```

**Solutions:**

1. **Database not started:**
   ```bash
   docker compose up -d audit-db
   ```

2. **Port conflict:**
   - Another PostgreSQL instance may be using port 9005
   - See [Network & Port Conflicts](#network--port-conflicts)

3. **Database not initialized:**
   ```bash
   # Recreate database with fresh state
   docker compose down -v
   docker compose up -d
   ```
   **Warning:** This deletes all audit logs.

---

### Problem: Audit Table Missing

**Error:**
```
ERROR: relation "mem0_audit_log" does not exist
```

**Solution:**

The audit table is created by the init script. Recreate the database:

```bash
# Check if init script exists
ls -la audit/init.sql

# Recreate audit database
docker compose down audit-db
docker volume rm docker_audit_data  # Warning: deletes audit logs
docker compose up -d audit-db

# Verify table exists
docker exec gov_mem0_audit_db psql -U audit -d audit -c "\dt"
```

Expected output:
```
          List of relations
 Schema |      Name       | Type  | Owner
--------+-----------------+-------+-------
 public | mem0_audit_log  | table | audit
```

---

## Network & Port Conflicts

### Problem: Port Already in Use

**Error:**
```
Error starting userland proxy: listen tcp 0.0.0.0:9000: bind: address already in use
```

**Diagnosis:**
```bash
# Find what's using the port (Linux/Mac)
lsof -i :9000

# Find what's using the port (Linux alternative)
netstat -tulpn | grep 9000

# Check all governance ports
for port in {9000..9006}; do
  lsof -i :$port
done
```

**Solutions:**

1. **Stop conflicting service:**
   ```bash
   # If another container is using the port
   docker ps
   docker stop <container-id>

   # If a system service is using the port
   sudo systemctl stop <service-name>
   ```

2. **Change port mapping:**
   Edit `docker/docker-compose.yml`:
   ```yaml
   gateway:
     ports:
       - "9100:8080"  # Use 9100 instead of 9000
   ```

   Update your API calls:
   ```bash
   curl http://localhost:9100/health  # Use new port
   ```

---

### Problem: Services Can't Communicate

**Symptoms:**
- Gateway can't reach OPA
- Gateway can't reach Mem0
- Services timeout

**Diagnosis:**
```bash
# Check Docker network
docker network ls
docker network inspect docker_default

# Test connectivity from gateway to OPA
docker exec gov_mem0_gateway ping -c 2 opa

# Test HTTP connectivity
docker exec gov_mem0_gateway curl http://opa:8181/health
```

**Solutions:**

1. **Ensure all services on same network:**
   - All services in `docker-compose.yml` should use default network
   - Or explicitly define a shared network

2. **Use service names, not localhost:**
   ```yaml
   # Correct (inside container)
   OPA_URL: http://opa:8181

   # Wrong (doesn't work inside container)
   OPA_URL: http://localhost:9001
   ```

3. **Restart networking:**
   ```bash
   docker compose down
   docker network prune
   docker compose up -d
   ```

---

## Performance Issues

### Problem: Slow API Responses

**Symptoms:**
- Requests take >1 second
- Gateway timeouts

**Diagnosis:**

1. **Check gateway logs for timing:**
   ```bash
   docker compose logs gateway | grep "took"
   ```

2. **Check OPA response time:**
   ```bash
   time docker exec gov_mem0_opa curl -X POST http://localhost:8181/v1/data/mem0/authz/allow \
     -d '{"input": {"action": "read", "roles": ["admin"]}}'
   ```

3. **Check database query performance:**
   ```bash
   docker exec gov_mem0_audit_db psql -U audit -d audit -c \
     "EXPLAIN ANALYZE SELECT * FROM mem0_audit_log ORDER BY timestamp DESC LIMIT 10;"
   ```

**Solutions:**

1. **Database connection pooling:**
   - Current implementation creates new connection per request
   - For production, implement connection pooling (see memory/MEMORY.md)

2. **Add database index on timestamp:**
   ```bash
   docker exec gov_mem0_audit_db psql -U audit -d audit -c \
     "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON mem0_audit_log(timestamp DESC);"
   ```

3. **OPA policy optimization:**
   - Keep policies simple
   - Avoid expensive operations in Rego

4. **Increase Docker resources:**
   - Docker Desktop: Settings → Resources → Increase RAM/CPU

---

### Problem: High Memory Usage

**Diagnosis:**
```bash
docker stats --no-stream
```

**Solutions:**

1. **Restart services:**
   ```bash
   docker compose restart
   ```

2. **Clear rate limiter state:**
   - Rate limiter uses in-memory storage
   - Restart gateway to clear: `docker compose restart gateway`

3. **Prune unused Docker resources:**
   ```bash
   docker system prune -a
   ```

---

## Docker Issues

### Problem: Docker Compose Not Found

**Error:**
```bash
docker: 'compose' is not a docker command.
```

**Solution:**

1. **Using Docker Compose V1 (legacy):**
   ```bash
   # Use docker-compose (with hyphen)
   docker-compose --version
   docker-compose up -d
   ```

2. **Install Docker Compose V2:**
   ```bash
   # Linux
   sudo apt-get update
   sudo apt-get install docker-compose-plugin

   # Mac (via Homebrew)
   brew install docker-compose
   ```

---

### Problem: Permission Denied

**Error:**
```
permission denied while trying to connect to Docker daemon
```

**Solution:**

```bash
# Add user to docker group (Linux)
sudo usermod -aG docker $USER

# Log out and back in, then verify
docker ps

# Or use sudo (not recommended)
sudo docker compose up -d
```

---

### Problem: Old Containers Won't Stop

**Symptoms:**
```bash
$ docker compose down
Error: container <id> is still running
```

**Solution:**

```bash
# Force stop all governance containers
docker ps -a | grep gov_mem0 | awk '{print $1}' | xargs docker stop
docker ps -a | grep gov_mem0 | awk '{print $1}' | xargs docker rm

# Nuclear option: stop all Docker containers
docker stop $(docker ps -aq)
docker rm $(docker ps -aq)
```

---

## Getting More Help

### Enable Debug Logging

**Gateway debug logs:**
Edit `gateway/middleware/main.py` and add at top:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

Rebuild and restart:
```bash
cd docker
docker compose build gateway
docker compose restart gateway
docker compose logs gateway -f
```

**OPA debug logs:**
Edit `docker/docker-compose.yml`:
```yaml
opa:
  command: ["run", "--server", "--log-level", "debug", "/policies"]
```

Restart:
```bash
docker compose restart opa
docker compose logs opa -f
```

---

### Collect Diagnostic Information

For bug reports, collect this information:

```bash
# System info
docker --version
docker compose version
uname -a

# Service status
docker compose ps

# Recent logs (all services)
docker compose logs --tail=100 > /tmp/governance-logs.txt

# OPA policy test results
docker exec gov_mem0_opa opa test /policies -v > /tmp/opa-tests.txt

# Audit log sample
docker exec gov_mem0_audit_db psql -U audit -d audit -c \
  "SELECT * FROM mem0_audit_log ORDER BY timestamp DESC LIMIT 5;" \
  > /tmp/audit-sample.txt

# Attach these files to your GitHub issue
```

---

### Additional Resources

- **[Quick Start Guide](./QUICKSTART.md)** - Setup from scratch
- **[API Examples](./API_EXAMPLES.md)** - Common usage patterns
- **[GitHub Issues](https://github.com/your-org/oss-governance-for-mem0/issues)** - Report bugs
- **[Architecture Docs](../README.md)** - Understand system design

---

**Still stuck?** [Open an issue](https://github.com/your-org/oss-governance-for-mem0/issues) with diagnostic information.
