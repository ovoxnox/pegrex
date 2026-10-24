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
