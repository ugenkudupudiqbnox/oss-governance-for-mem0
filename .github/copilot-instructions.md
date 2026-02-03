# Governance Pack for Mem0 - AI Coding Instructions

This repository provides governance, security, audit, and compliance sidecar controls for Mem0 (OSS). It is designed to enable Mem0 deployments in enterprise and regulated environments (SOC 2, ISO 27001, HIPAA).

## ⚠️ Hard Constraints
- **Zero Mem0 Modifications**: NEVER modify Mem0 source code. Treat it as an external, black-box service.
- **Affiliation**: DO NOT claim or imply official affiliation with Mem0. Use neutral, third-party language.
- **Licensing**: All contributions must be Apache-2.0 compatible. Avoid non-permissive or proprietary dependencies.
- **Security Defaults**: Always follow **deny-by-default** and **least-privilege** principles.
- **Secrets**: NEVER hard-code secrets. Assume external secret management (e.g., HashiCorp Vault).

## Architecture & Design Patterns
- **Sidecar/Gateway Pattern**: Enforce controls *around* Mem0 using identity, policy, and audit layers.
- **Multi-Tenancy**: Assume multi-tenant and multi-agent deployments by default. Ensure strong tenant isolation.
- **RBAC Roles**: Use explicit roles: `admin`, `agent-writer`, `agent-reader`, and `auditor`.
- **Separation of Concerns**: Keep IAM, Policy, Audit, and Observability logic strictly separated.

## Implementation Guidelines
- **Audit Logging**: Every sensitive action (write, delete, access) must produce an append-only, tamper-evident log including: `Actor`, `Role`, `Tenant`, `Action`, `Resource`, `Timestamp`, and `Outcome`.
- **Policy-as-Code**: Prefer declarative authorization rules (e.g., OPA/Rego). Avoid "magic" or implicit behavior.
- **Production-Grade**: Write infrastructure-quality code with strong typing, validation, and minimal dependencies.
- **Traceability**: Prioritize verbose logging and explainability over brevity or convenience.
- **Logic Documentation**: Explain *why* a control exists (e.g., mapping to SOC 2 CC6.1) in comments.

## Policy & Compliance Mindset
- **Audit-First**: Every governance decision must be defensible during a security audit.
- **Correctness Over Features**: If a tradeoff exists, always prioritize security, auditability, and compliance over new features or user convenience.
- **Neutral Language**: Use professional, objective language suitable for enterprise security reviews.

## Key Directories
- `policies/`: Declarative authorization rules (planned).
- `compliance/`: SOC 2/ISO 27001 mappings and evidence templates (planned).
- `audit/`: Schema and logic for immutable logging (planned).

Refer to [README.md](README.md) for the high-level architectural vision and help maintain it as new capabilities are added.
