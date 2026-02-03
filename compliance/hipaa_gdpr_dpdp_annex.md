# HIPAA, GDPR & DPDP Annex

This annex describes how Governance Pack for Mem0 supports privacy and data
protection requirements. It is not legal advice.

## HIPAA (Technical Safeguards)

- Access control: Unique user identification via IAM
- Audit controls: Immutable audit logs
- Integrity: Policy enforcement and tamper-evident logging
- Transmission security: TLS assumed at transport layer

## GDPR (Selected Articles)

### Article 5 – Data Minimization & Purpose Limitation
- Memory access governed by explicit policies
- Least-privilege enforcement

### Article 30 – Records of Processing
- Audit logs act as processing records

### Article 32 – Security of Processing
- RBAC, policy enforcement, logging, and monitoring

### Article 33 – Breach Detection
- Centralized logging and alerting

## India DPDP Act (2023)

- Purpose limitation via policy-as-code
- Access logging for all personal data actions
- Support for audit and accountability requirements

## Data Subject Rights
- Memory access and deletion events are auditable
- Enables downstream fulfillment by application owners
