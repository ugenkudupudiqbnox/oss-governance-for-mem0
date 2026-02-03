# Incident Response Playbook
Governance Pack for Mem0

This playbook provides a reference incident response process for deployments
using Governance Pack for Mem0. It aligns with SOC 2 and ISO 27001 expectations.

---

## Objectives
- Detect, respond to, and contain security incidents
- Preserve evidence for audits and investigations
- Restore normal operations safely
- Prevent recurrence

---

## Incident Classification

### Severity Levels
- **SEV-1 (Critical)**: Data breach, cross-tenant access, credential compromise
- **SEV-2 (High)**: Unauthorized access attempt, policy bypass attempt
- **SEV-3 (Medium)**: Suspicious behavior, failed authorization spikes
- **SEV-4 (Low)**: Misconfiguration, non-security operational issue

---

## Detection & Identification

### Signals
- OPA policy denials spike
- Audit log anomalies (unexpected write/delete)
- IAM alerts (failed logins, MFA bypass attempts)
- Infrastructure alerts (gateway, DB access)

### Evidence Sources
- Audit logs (PostgreSQL)
- Policy decision logs (OPA)
- Gateway access logs (NGINX/Kong)
- IAM logs (Keycloak)
- Grafana dashboards

---

## Containment

### Immediate Actions
- Revoke affected credentials or tokens
- Disable compromised agent or user
- Apply restrictive policies (deny writes)
- Isolate affected tenant if required

### Short-Term Containment
- Rotate secrets via secrets manager
- Increase logging verbosity
- Preserve logs and snapshots

---

## Eradication

- Remove malicious agents or integrations
- Patch misconfigurations or policy gaps
- Review IAM role assignments
- Validate policy-as-code logic

---

## Recovery

- Restore normal access gradually
- Monitor for recurrence
- Validate audit logging continuity
- Notify stakeholders if required

---

## Post-Incident Activities

### Root Cause Analysis
- What happened?
- Which control failed or was bypassed?
- Detection gaps?

### Evidence Retention
- Preserve logs and artifacts
- Document timeline and actions taken

### Improvements
- Update policies
- Enhance monitoring and alerts
- Update this playbook

---

## Compliance Considerations

### SOC 2
- Demonstrates CC7 (incident detection and response)
- Provides documented response procedures

### ISO 27001
- Supports Annex A.16 (Information security incident management)

### GDPR / DPDP
- Supports breach assessment and reporting timelines
- Enables accountability and traceability

---

## Roles & Responsibilities

- **Incident Commander**: Overall coordination
- **Security Engineer**: Investigation and containment
- **Platform Admin**: Access control changes
- **Compliance Officer**: Evidence and reporting

---

## Testing & Review
- Conduct tabletop exercises quarterly
- Review playbook annually or after major incidents
