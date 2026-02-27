# OPA Quick Start for Agents/Bots

Open Policy Agent (OPA) is a policy engine that lets you define and enforce access rules for APIs and services—without changing your application code.

## Why OPA?

- **Deny-by-default:** Only explicitly allowed actions are permitted.
- **RBAC & Tenant Isolation:** Enforce who can do what, for which tenant.
- **Auditability:** Every decision is explainable and logged.

## How Does It Work Here?

- You write policies in `.rego` files (see `policies/`).
- The gateway checks every request with OPA before forwarding to Mem0.
- If OPA says "allow," the request goes through; otherwise, it’s denied.

## Example: Allow Agent to Create a Ticket

```rego
package mem0.authz

default allow = false

allow {
    input.action == "write"
    input.roles[_] == "agent-writer"
    input.tenant == input.resource_tenant
}
```

## Testing Your Policy

Run this in your repo root:
```bash
opa test policies/ -v
```
You’ll see which roles/actions are allowed or denied.

## What Do I Need to Do?

- Set your agent’s role and tenant in request headers (`X-User-Role`, `X-Tenant-Id`).
- Make sure your action (read/write) is allowed by the policy.
- If denied, update the policy or request as needed.

## Learn More

- [OPA Official Docs](https://www.openpolicyagent.org/docs/latest/)
- [Rego Policy Language](https://www.openpolicyagent.org/docs/latest/policy-language/)
- [Playground: Try Policies Online](https://play.openpolicyagent.org/)

---

**Tip:**  
You don’t need to be an OPA expert—just copy, test, and tweak the example policies for your agent’s needs. All governance checks are handled by the toolkit.
