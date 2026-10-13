# Sentriq AI Security Suite v5

Sentriq is a local-first application security review console for authorized assessments. It combines bounded active checks, static source review, passive HTTPS inspection, Supabase/PostgreSQL RLS query templates, and evidence-backed reporting.

## Windows quick start
1. Extract this ZIP into a folder you control.
2. Double-click `run_agent.bat`.
3. Open `http://127.0.0.1:8501` if the browser does not open automatically.
4. Run `python -m unittest discover -s tests -v` to execute local tests.

## Modules
- **SQL Injection Engine:** error-signature, Boolean differential, short time-delay, and UNION signal checks. Hard cap: 10 GET requests per probe session; time-delay payloads are capped at 2 seconds. Stacked-query execution and WAF-evasion/obfuscation payloads are disabled. This detects signals; it does not automatically prove exploitability.
- **Authentication Matrix:** missing/invalid-token boundaries, local JWT claim review, and session-cookie/cache attributes. Use only dedicated test-account tokens.
- **Access Control Matrix:** two-account IDOR/BOLA checks on synthetic records and role-boundary checks. Avoid real customer records.
- **Database Lockdown:** API/gateway exposure checks plus read-only RLS, grant, function, and storage-policy SQL templates. SQL templates must be reviewed before execution.
- **Execution Dossier:** consolidated evidence, conservative PASS/FAIL/MANUAL REVIEW verdicts, severity estimates, remediation guidance, and multi-format reports.
- **Offline credential-stuffing simulator:** models simple per-account/per-source throttling using synthetic counters; it makes zero network requests and uses no credentials.
- **Manual defensive-control checklist:** records operator-attested results for rate limiting, credential-stuffing resistance, MFA, JWT validation, session rotation/revocation, and cookie attributes. These are not independently tested by the checklist.
- **Source & Passive Audit:** source bundle inspection and passive HTTPS header review.

## Active testing guardrails
- Active probes require a confirmation checkbox and the exact phrase `RUN AUTHORIZED TESTS` in the UI.
- Use only systems you own or have explicit written authorization to assess. Prefer staging with synthetic records and read-only endpoints.
- Active SQLi checks use HTTPS, same-origin enforcement, GET-only requests, no redirect following, a 10-request hard cap, and a short 2-second time-delay test. A request budget may stop some vectors early.
- Do not supply service-role/secret keys, production admin tokens, or real customer credentials. Tokens are held in process memory for the run and are not intentionally placed in reports.
- No password brute force, real credential stuffing, session theft, destructive database operations, or bulk enumeration is implemented. Rate-limit and session lifecycle defenses should be validated with a dedicated canary account and staging-specific procedures.
- Never expose Streamlit's port to the public internet; the included launcher binds to loopback.

## How to interpret verdicts
- **FAIL:** a detector observed a potentially serious weakness or the operator reported a failed control. Reproduce and verify impact before calling it a confirmed vulnerability.
- **PASS:** only used for narrow checks where expected enforcement was observed or the operator marked a control verified. A PASS does not certify the whole application.
- **MANUAL REVIEW:** evidence is incomplete, heuristic, self-attested, or a test found no signal. No signal does not prove security.

## Limitations
Sentriq is a learning and assessment tool, not a substitute for code review, threat modeling, secure development, professional penetration testing, or continuous monitoring. CVSS/risk scoring is heuristic. It cannot reliably discover every SQL injection, broken login, IDOR, or database policy error. DNS, proxies, caching, API behavior, and false positives can affect results.

## Database review
The SQL file in `sql/` is intended for read-only inspection of metadata such as RLS status, policies, grants, functions, and storage configuration. Review the queries and run them in the intended project as an authorized database administrator. Metadata inspection alone cannot prove row-level policies are correct; verify using anonymous, User A, User B, and owner test identities.
