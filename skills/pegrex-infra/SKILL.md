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
- `policy.analyze_iac` also covers Kubernetes, Helm, Dockerfiles, IAM JSON/YAML,
  and NetworkPolicy world CIDRs. Preserve its parser-specific confidence and
  subset coverage. Helm templates are statically masked, not evaluated; template
  gaps and parser failures are UNKNOWN, never clean deployment evidence.

## Proof-carrying releases
- `create_proof_carrying_release` joins API contract identities, SBOM, build
  attestation, previous-release semantic diff, and a machine-checkable UNKNOWN
  summary. `verify_release_pack` rechecks all supplied upstreams.
- Unsigned build provenance verifies available hashes only. It does not authenticate
  builder identity or hermeticity and must not become an authenticated release claim.
