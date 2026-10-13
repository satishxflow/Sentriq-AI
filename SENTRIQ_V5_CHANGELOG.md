# Sentriq AI v5 — Change Summary

This release strengthens the previous suite with conservative verdicts, bounded probes, explicit authorization confirmation, a defensive authentication-control checklist, and remediation examples.

- SQL injection: retains error-based, Boolean, time-based, and UNION signal checks; caps a probe session at 10 GET requests and shortens delay probes to 2 seconds. Stacked-query and WAF-evasion payloads are disabled.
- Authentication: preserves token-boundary and local JWT/cookie analysis; adds a zero-network synthetic credential-stuffing simulator and operator-attested review of rate limiting, credential-stuffing resistance, MFA, session rotation/revocation, and JWT validation. No credential-stuffing attempts are sent.
- Access control: keeps separate-account synthetic-record tests and admin-route boundary checks. Do not use real customer records.
- Database lockdown: retains API exposure checks and the RLS audit SQL template.
- Execution dossier: every finding receives PASS, FAIL, or MANUAL REVIEW; no-signal results are not marked as proof of safety. Report dashboard field mappings were corrected.
- Safety: active modules require a checkbox and exact confirmation phrase. Reports should still be reviewed before sharing.

See README.md for use, limits, and test commands.
