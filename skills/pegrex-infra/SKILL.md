---
name: pegrex-infra
description: Verify infrastructure-as-code (Zelkova-style IAM evaluation, Terraform findings) and sign provenance (SLSA-style attestations). Use for cloud-policy gates.
---

# IaC + provenance

- `iac.can(statements, action, resource)`: explicit-deny wins,
  default-deny. `audit_policy` flags wildcard admin; `audit_terraform`
  flags public-read buckets.
- `slsa.attest(...)` / `verify(...)`: HMAC-signed provenance with
  per-material hashing. `publish_sigstore` REFUSES offline -- never
  pretends publication happened.
