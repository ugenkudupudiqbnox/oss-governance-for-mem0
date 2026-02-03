# Docker Compose Reference Stack

This Docker Compose stack provides a **reference governance environment**
for Governance Pack for Mem0.

## Included Services
- PostgreSQL: audit log storage
- OPA: policy-as-code engine
- Keycloak: IAM (dev mode)
- Grafana + Loki: observability

## Usage
```bash
cd docker
docker compose up -d
```

This stack is for **local testing and reference only**.
Production deployments should harden configuration and credentials.
