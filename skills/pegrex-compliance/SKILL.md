---
name: pegrex-compliance
description: GDPR data-flow findings, SOC2 control presence, legal-deadline CI artifacts. Use for regulated-codebase audits.
---

# compliance as code

- `compliance.audit_gdpr(src)`: PII -> consent-gated sink without a
  consent call is a finding that names the flow.
- `compliance.audit_soc2(src, controls)`: required patterns on PII paths.
- `legalci.report_clauses(clauses, today=...)`: deadlines WITHOUT a
  base date are "not evaluable", never fake-future. Supply base dates.

## Dependency and build evidence
- `scan_reachable` separates installed vulnerable packages from reachable declared
  vulnerable calls. `not-observed` is not absence; missing symbols are UNKNOWN.
- `generate_sbom(..., format="cyclonedx"|"spdx")` includes graph, hashes,
  licenses, and lockfile provenance without inventing missing metadata.
- `check_lockfile_policy` checks pins, URLs, VCS commits, and integrity. Typo
  similarity is a review signal, not a maliciousness determination.
- `create_build_provenance` emits in-toto/SLSA-shaped statements with verifiable
  subjects/materials. Unsigned statements do not authenticate builder identity.

## Source-bounded control evidence
- `create_compliance_pack` maps executable flow contracts and source observations
  to controls. Distinguish technical source evidence from operational effectiveness.
- Organizational, legal, procedural, and runtime controls are not provable from
  source and remain UNKNOWN. Never emit a legal conclusion, certification,
  attestation, or overall compliance determination from these packs.
- `build_compliance_map` joins classifications, traces, retention/deletion functions,
  and infrastructure controls for bounded queries. Static lifecycle mappings do not
  prove operational effectiveness. Legal interpretation is human-required/reviewed,
  never proved by code alone.
