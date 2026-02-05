# Documentation

User documentation for the Governance Pack for Mem0.

---

## Getting Started

New to the project? Start here:

1. **[Quick Start Guide](./QUICKSTART.md)** ⭐
   - Get up and running in under 10 minutes
   - Prerequisites, installation, first API calls
   - Health checks and verification

2. **[API Usage Examples](./API_EXAMPLES.md)**
   - curl and Python SDK examples
   - Multi-tenant operations
   - Rate limiting patterns
   - Error handling

3. **[JavaScript/TypeScript Examples](./API_EXAMPLES_JAVASCRIPT.md)** ⭐ NEW
   - TypeScript client library with full typing
   - Node.js and browser examples
   - Express.js middleware integration
   - Multi-tenant patterns
   - Advanced error handling and retry logic

---

## Guides

### Common Tasks

- **[Common Scenarios](./COMMON_SCENARIOS.md)**
  - Multi-tenant SaaS setup
  - Custom RBAC roles
  - Production rate limiting with Redis
  - Integrating with existing Mem0
  - Compliance audit workflows
  - High availability deployment
  - Time-based access policies

- **[Troubleshooting Guide](./TROUBLESHOOTING.md)**
  - Service startup issues
  - Gateway errors (400, 403, 429, 503)
  - OPA policy debugging
  - Database connection problems
  - Port conflicts
  - Performance tuning

### Programming Languages

- **[Python Examples](./API_EXAMPLES.md)** - Python SDK with requests library
- **[JavaScript/TypeScript](./API_EXAMPLES_JAVASCRIPT.md)** - Node.js, Express.js, TypeScript client
- **[Java Examples](./API_EXAMPLES_JAVA.md)** ⭐ NEW - OkHttp, Spring Boot, Maven/Gradle
- **[Go Examples](./API_EXAMPLES_GO.md)** ⭐ NEW - net/http, Gin framework, Go modules

---

## Architecture & Design

- **[Project README](../README.md)** - Overview and design principles
- **[CLAUDE.md](../CLAUDE.md)** - Development conventions
- **[Threat Model](../architecture/threat-model.md)** - Security considerations
- **[Docker Stack](../docker/README.md)** - Service architecture
- **[Testing Guide](../gateway/middleware/README_TESTS.md)** - Test suite details

---

## Compliance

- **[Controls Mapping](../compliance/controls-mapping.md)** - SOC 2, ISO 27001
- **[SOC 2 Evidence Checklist](../compliance/soc2_evidence_checklist.md)**
- **[HIPAA/GDPR/DPDP Annex](../compliance/hipaa_gdpr_dpdp_annex.md)**
- **[Data Retention & Deletion](../compliance/data_retention_deletion.md)**
- **[Incident Response Playbook](../incident-response/incident_response_playbook.md)**

---

## Reference

### RBAC Roles

| Role | Read | Write | Delete | Audit | Rate Limit |
|------|------|-------|--------|-------|------------|
| **admin** | ✅ | ✅ | ✅ | ✅ | 500/min |
| **agent-writer** | ✅ | ✅ | ❌ | ❌ | 100/min |
| **agent-reader** | ✅ | ❌ | ❌ | ❌ | 100/min |
| **auditor** | ❌ | ❌ | ❌ | ✅ | 100/min |

All roles are tenant-isolated (users can only access their own tenant's data).

### Service Ports

| Service | Port | Description |
|---------|------|-------------|
| Gateway | 9000 | Main API endpoint (governed) |
| OPA | 9001 | Policy engine |
| Keycloak | 9002 | Identity and access management |
| Grafana | 9003 | Dashboards and analytics |
| Loki | 9004 | Log aggregation |
| Audit DB | 9005 | PostgreSQL audit trail |
| Mem0 | 9006 | Memory backend |

### Configuration Environment Variables

**Gateway:**
- `OPA_URL` - OPA policy endpoint (default: `http://opa:8181/v1/data/mem0/authz/allow`)
- `MEM0_URL` - Mem0 backend URL (default: `http://mem0:8000`)
- `DB_HOST`, `DB_NAME`, `DB_USER`, `DB_PASS` - Audit database connection
- `RATE_LIMIT_REQUESTS` - Requests per window for non-admin (default: 100)
- `RATE_LIMIT_WINDOW_SECONDS` - Rate limit window (default: 60)
- `RATE_LIMIT_ADMIN_REQUESTS` - Admin requests per window (default: 500)
- `MAX_BODY_SIZE_BYTES` - Max request body size (default: 1048576 = 1MB)

---

## Quick Links

- **[GitHub Repository](https://github.com/your-org/oss-governance-for-mem0)**
- **[Issue Tracker](https://github.com/your-org/oss-governance-for-mem0/issues)**
- **[License](../LICENSE)** - Apache 2.0

---

## Documentation for Developers

Building or contributing to the project? See:

- **[CLAUDE.md](../CLAUDE.md)** - Development conventions and recent decisions
- **[Testing Guide](../gateway/middleware/README_TESTS.md)** - Running tests
- **[OPA Policies](../policies/)** - Policy development
- **[Gateway Source](../gateway/middleware/main.py)** - Gateway implementation

---

## Need Help?

1. Check the **[Troubleshooting Guide](./TROUBLESHOOTING.md)** first
2. Search **[existing issues](https://github.com/your-org/oss-governance-for-mem0/issues)**
3. **[Open a new issue](https://github.com/your-org/oss-governance-for-mem0/issues/new)** with details

---

**Ready to get started?** → [Quick Start Guide](./QUICKSTART.md)
