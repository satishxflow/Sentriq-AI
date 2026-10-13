# Sentriq AI v5 — Security Suite

Sentriq v5 builds on the supplied Sentriq AI Security Suite with bounded active checks, more honest evidence verdicts, additional defensive authentication review, and an offline credential-stuffing simulation.

## Five requested engines

1. **SQL Injection Engine** — error-based, Boolean differential, short time-delay, and UNION signal checks. The per-session hard cap is 10 GET requests; time delays are limited to 2 seconds. Stacked-query execution and WAF-evasion/obfuscation payloads are disabled. Includes parameterized-query remediation examples.
2. **Authentication Matrix** — missing/invalid token boundaries, local JWT claim analysis, cookie/session/cache checks, and a manual control checklist for rate limiting, credential-stuffing resistance, MFA, session rotation/revocation, and JWT validation.
3. **Access Control Matrix** — cross-account IDOR/BOLA checks with two dedicated test users and synthetic records, plus limited role-boundary checks.
4. **Database Lockdown** — API/gateway exposure checks and read-only SQL templates for RLS, grants, functions, and storage-policy review.
5. **Execution Dossier** — consolidated findings, risk estimates, CWE/OWASP mapping, remediation roadmap, and HTML/Markdown/JSON/executive report output. Findings are labeled PASS, FAIL, or MANUAL REVIEW; absence of a signal is never presented as proof that an application is secure.

Additional capabilities include static source review, passive HTTPS inspection, exact-phrase authorization confirmation, and a zero-network synthetic credential-stuffing defense simulator.

## Verification

Local checks completed for this release:
- Python compilation succeeded for app, scanner, and engine modules.
- 18 automated tests passed, including tests for request caps, disabled stacked queries/WAF evasion, report verdicts, self-attested controls, and the offline simulator.
- The Streamlit UI was not launched in this build environment because Streamlit is not installed here; the included Windows launcher installs requirements before starting the local app.

## Important limitations

This is a learning and assessment tool, not a guarantee of complete vulnerability discovery. It does not run real credential stuffing or session theft tests, and the synthetic simulator is not a live identity-provider assessment. Use only against systems you own or have explicit authorization to assess, preferably in staging with synthetic data.
