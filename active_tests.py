"""Bounded, read-only active checks for an explicitly authorized HTTPS origin.

No form submission, state-changing HTTP methods, crawling, brute force, or data export.
Tokens and API keys are used only in-memory for requests and never placed in reports.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional

USER_AGENT = "Pecuvea-Security-Agent/3.1 (authorized controlled read-only test)"
MAX_BODY_BYTES = 1_000_000
MIN_REQUEST_INTERVAL_SECONDS = 0.75

SQL_ERROR_PATTERNS = [
    r"SQL syntax.{0,80}error",
    r"sqlite(?:3)?\.(?:OperationalError|DatabaseError|ProgrammingError)",
    r"psycopg2\.(?:errors|Error)",
    r"postgres(?:ql)?.{0,40}(?:syntax error|error)",
    r"mysql.{0,50}(?:syntax|error)",
    r"unterminated quoted string",
    r"ORA-\d{4,5}",
    r"SQLSTATE\[[0-9A-Z]{5}\]",
    r"SequelizeDatabaseError",
    r"PrismaClientKnownRequestError",
    r"PG::SyntaxError",
    r"Microsoft ODBC SQL Server Driver",
]
ERROR_RE = re.compile("|".join(f"(?:{p})" for p in SQL_ERROR_PATTERNS), re.IGNORECASE)
BLOCKED_SQL_PATH_PARTS = {
    "login", "signin", "sign-in", "auth", "token", "password", "checkout",
    "payment", "payments", "purchase", "purchases", "delete", "update",
    "insert", "transfer", "refund", "webhook", "logout", "session",
}
SENSITIVE_QUERY_NAMES = {"token", "access_token", "apikey", "api_key", "password", "secret", "authorization"}


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Do not follow redirects during active probes."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _url_parts(url: str):
    p = urllib.parse.urlsplit((url or "").strip())
    if p.scheme.lower() != "https" or not p.hostname:
        raise ValueError("Use a valid HTTPS URL. Active checks do not accept HTTP targets.")
    if p.username or p.password:
        raise ValueError("Do not put credentials in a URL.")
    if p.fragment:
        p = p._replace(fragment="")
    return p


def _origin(p) -> tuple[str, str, int]:
    port = p.port or (443 if p.scheme.lower() == "https" else 80)
    return p.scheme.lower(), (p.hostname or "").lower(), port


def validate_scope(target_root: str, endpoint_url: str) -> str:
    """Return the normalized endpoint after enforcing HTTPS same-origin scope."""
    root = _url_parts(target_root)
    endpoint = _url_parts(endpoint_url)
    if _origin(root) != _origin(endpoint):
        raise ValueError("Endpoint must use the exact same HTTPS origin (scheme, hostname, and port) as the authorized target.")
    for key, _ in urllib.parse.parse_qsl(endpoint.query, keep_blank_values=True):
        if key.lower() in SENSITIVE_QUERY_NAMES:
            raise ValueError("Do not place tokens, API keys, passwords, or secrets in query parameters. Use the designated local-only credential fields.")
    return urllib.parse.urlunsplit((endpoint.scheme, endpoint.netloc, endpoint.path or "/", endpoint.query, ""))


def _looks_like_service_role_jwt(value: str) -> bool:
    # Supabase legacy keys are JWT-shaped. Decode only the payload for this local safety check;
    # never emit the token or its decoded claims into reports.
    parts = value.split(".")
    if len(parts) != 3:
        return False
    try:
        payload = parts[1] + ("=" * (-len(parts[1]) % 4))
        claims = json.loads(base64.urlsafe_b64decode(payload.encode("ascii")).decode("utf-8"))
        return str(claims.get("role", "")).lower() == "service_role"
    except Exception:
        return False


def _check_credentials(token: Optional[str], publishable_key: Optional[str]) -> None:
    for name, value in (("token", token), ("API key", publishable_key)):
        v = (value or "").strip()
        if re.search(r"service[_-]?role|sb_secret_", v, re.IGNORECASE) or _looks_like_service_role_jwt(v):
            raise ValueError("A service-role/secret key was detected. Do not use it in this agent; use test-user tokens and a publishable/anon key only.")


def _headers(token: Optional[str] = None, publishable_key: Optional[str] = None) -> dict[str, str]:
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json,text/html;q=0.8,*/*;q=0.5", "Cache-Control": "no-cache"}
    if publishable_key and publishable_key.strip():
        headers["apikey"] = publishable_key.strip()
    if token and token.strip():
        headers["Authorization"] = "Bearer " + token.strip()
    return headers


def _request_get(url: str, headers: dict[str, str], timeout: int = 8) -> dict[str, Any]:
    """Perform one GET, returning a minimal response summary (never body content)."""
    req = urllib.request.Request(url, headers=headers, method="GET")
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        NoRedirectHandler(),
    )
    try:
        with opener.open(req, timeout=timeout) as r:
            status, resp_headers, body = r.status, r.headers, r.read(MAX_BODY_BYTES)
    except urllib.error.HTTPError as e:
        # HTTPError also covers redirects because redirect following is disabled.
        status, resp_headers, body = e.code, e.headers, e.read(MAX_BODY_BYTES)
    except Exception as e:
        # Deliberately avoid placing exception strings in reports; they may contain sensitive URL details.
        return {"status": None, "content_type": "", "bytes": 0, "json_kind": "unavailable", "item_count": None,
                "has_structured_data": False, "sql_error_signature": False, "error_type": type(e).__name__}
    content_type = resp_headers.get("Content-Type", "")
    try:
        obj = json.loads(body.decode("utf-8", "replace"))
        is_json = True
    except Exception:
        obj = None
        is_json = False
    kind = "json" if is_json else ("html" if "html" in content_type.lower() or body.lstrip().lower().startswith((b"<!doctype html", b"<html")) else "other")
    count: Optional[int] = None
    has_data = False
    if is_json:
        if isinstance(obj, list):
            count = len(obj); has_data = len(obj) > 0
        elif isinstance(obj, dict):
            error_keys = {"error", "errors", "message", "code", "details", "hint"}
            if not (set(k.lower() for k in obj.keys()) & error_keys):
                if "data" in obj:
                    dv = obj.get("data")
                    has_data = bool(dv)
                    if isinstance(dv, list): count = len(dv)
                elif "results" in obj:
                    rv = obj.get("results")
                    has_data = bool(rv)
                    if isinstance(rv, list): count = len(rv)
                elif "items" in obj:
                    iv = obj.get("items")
                    has_data = bool(iv)
                    if isinstance(iv, list): count = len(iv)
                else:
                    has_data = len(obj) > 0
                    count = len(obj)
    body_text = body.decode("utf-8", "replace")
    return {
        "status": status,
        "content_type": content_type[:120],
        "bytes": len(body),
        "json_kind": kind,
        "item_count": count,
        "has_structured_data": has_data,
        "sql_error_signature": bool(ERROR_RE.search(body_text)),
        # Only a short hash is kept in memory for response comparison; raw response bodies are never saved.
        "body_signature": hashlib.sha256(body).hexdigest()[:16],
    }


def _signature(response: dict[str, Any]) -> tuple[Any, ...]:
    return response.get("status"), response.get("bytes"), response.get("body_signature")


def _status_family(status: Optional[int]) -> str:
    if status is None: return "network_error"
    if 200 <= status < 300: return "2xx"
    if status in (401, 403): return "denied"
    if status == 404: return "not_found"
    if 300 <= status < 400: return "redirect_blocked"
    return str(status)


def _assert_sql_probe_endpoint(path: str) -> None:
    parts = {p.lower() for p in path.split("/") if p}
    blocked = parts & BLOCKED_SQL_PATH_PARTS
    if blocked:
        raise ValueError("SQL probes are blocked on sensitive route names (" + ", ".join(sorted(blocked)) + "). Use a read-only search/detail endpoint in staging with synthetic data; do not test login, payment, order, write, or session routes here.")


def sql_injection_probe(
    target_root: str,
    endpoint_url: str,
    parameter: str,
    base_value: str,
    mode: str = "syntax",
    context: str = "string",
    bearer_token: Optional[str] = None,
    publishable_key: Optional[str] = None,
    timeout: int = 8,
) -> dict[str, Any]:
    """Run <=3 syntax requests or <=3 boolean-differential requests, all GET-only.

    Intended only for a read-only query/search endpoint in a staging clone with synthetic data.
    The function does not crawl, submit forms, enumerate records, or follow redirects.
    """
    endpoint = validate_scope(target_root, endpoint_url)
    _assert_sql_probe_endpoint(urllib.parse.urlsplit(endpoint).path)
    _check_credentials(bearer_token, publishable_key)
    if not parameter or len(parameter) > 100:
        raise ValueError("Enter one query parameter name (max 100 characters).")
    if not base_value or len(base_value) > 300:
        raise ValueError("Enter a representative non-empty test value (max 300 characters).")
    if mode not in ("syntax", "boolean"):
        raise ValueError("Mode must be syntax or boolean.")
    if context not in ("string", "numeric"):
        raise ValueError("Context must be string or numeric.")
    if context == "numeric" and not re.fullmatch(r"-?\d{1,18}", base_value):
        raise ValueError("Numeric context requires a plain integer as the base value.")

    p = urllib.parse.urlsplit(endpoint)
    pairs = urllib.parse.parse_qsl(p.query, keep_blank_values=True)
    found = any(k == parameter for k, _ in pairs)
    pairs = [(k, v) for k, v in pairs if k != parameter]
    pairs.append((parameter, base_value))

    def build_url(value: str) -> str:
        q = [(k, v) for k, v in pairs if k != parameter]
        q.append((parameter, value))
        return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path, urllib.parse.urlencode(q, doseq=True), ""))

    headers = _headers(bearer_token, publishable_key)
    reqs = []
    labels = []
    if mode == "syntax":
        tests = [("baseline", base_value), ("single_quote", base_value + "'"), ("double_quote", base_value + '"')]
    elif context == "string":
        tests = [("baseline", base_value), ("true_condition", base_value + "' AND '1'='1"), ("false_condition", base_value + "' AND '1'='2")]
    else:
        tests = [("baseline", base_value), ("true_condition", base_value + " AND 1=1"), ("false_condition", base_value + " AND 1=2")]
    if len(tests) > 3:
        tests = tests[:3]
    for label, value in tests:
        if reqs: time.sleep(MIN_REQUEST_INTERVAL_SECONDS)
        response = _request_get(build_url(value), headers, timeout=timeout)
        reqs.append({"test": label, **response})
        labels.append(label)

    baseline = reqs[0]
    findings: list[dict[str, Any]] = []
    quote_errors = [r for r in reqs[1:] if r.get("sql_error_signature")]
    status_anomaly = [r for r in reqs[1:] if r.get("status") is not None and r.get("status") >= 500 and baseline.get("status") is not None and baseline.get("status") < 500]
    if quote_errors or status_anomaly:
        findings.append({
            "severity": "medium",
            "title": "Potential SQL-injection or database-error signal",
            "status": "signal_needs_manual_verification",
            "evidence": "A quote probe triggered a recognizable database error signature or changed the baseline into a server error. The response body was not retained.",
            "recommendation": "Reproduce only in staging, inspect server-side logs, use parameterized queries/prepared statements, and ensure detailed database errors are not returned to clients.",
            "confidence": "low-to-medium",
        })
    if mode == "boolean":
        true_r = next(r for r in reqs if r["test"] == "true_condition")
        false_r = next(r for r in reqs if r["test"] == "false_condition")
        # Require the true condition to match the baseline exactly and the false condition to differ.
        # This is still only a signal: caching, filtering semantics, or application behavior can mimic it.
        if _signature(true_r) == _signature(baseline) and _signature(false_r) != _signature(baseline) and not false_r.get("sql_error_signature"):
            findings.append({
                "severity": "high",
                "title": "Potential boolean-based SQL injection response differential",
                "status": "strong_signal_not_proof",
                "evidence": "The true-condition response matched the baseline signature while the false-condition response differed. Only status, byte count, and a short body hash were compared; response bodies were not retained.",
                "recommendation": "Treat this as a strong lead, not final proof. In staging, reproduce with a controlled test case and verify query construction in server-side code/logs. Fix with parameterized queries and retest.",
                "confidence": "medium",
            })
        elif _signature(true_r) != _signature(false_r):
            findings.append({
                "severity": "info",
                "title": "Boolean-condition responses differ; manual review needed",
                "status": "inconclusive_differential",
                "evidence": "True/false condition requests produced different response signatures. Ordinary application behavior can cause this; no exploitability is confirmed.",
                "recommendation": "Inspect the endpoint implementation and repeat against synthetic staging data. Do not treat response differences alone as a confirmed vulnerability.",
                "confidence": "low",
            })
    if not findings:
        findings.append({
            "severity": "info",
            "title": "No SQL-injection signal detected by this limited probe",
            "status": "not_detected_not_proof_of_safety",
            "evidence": "The bounded GET-only probes did not observe the configured SQL error signatures or a strong Boolean response differential.",
            "recommendation": "This does not prove the endpoint is safe. Review server-side query construction and test additional input paths in staging.",
            "confidence": "low",
        })
    return {
        "target_origin": "{}://{}{}".format(p.scheme, p.hostname, (":" + str(p.port)) if p.port else ""),
        "endpoint_path": p.path,
        "test_type": "controlled_read_only_sql_injection_probe",
        "parameter": parameter,
        "mode": mode,
        "context": context,
        "requests_sent": len(reqs),
        "response_summaries": [{k: v for k, v in r.items() if k != "body_signature"} for r in reqs],
        "findings": findings,
        "credentials_included_in_report": False,
        "response_bodies_saved": False,
        "note": "Use only on a read-only staging endpoint with synthetic data. Requests are GET-only, same-origin, rate-limited, and redirects are not followed.",
    }


def _summarize_response_for_report(r: dict[str, Any]) -> dict[str, Any]:
    keep = ("status", "content_type", "bytes", "json_kind", "item_count", "has_structured_data", "sql_error_signature", "error_type")
    return {k: r.get(k) for k in keep}


def authentication_boundary_test(
    target_root: str,
    protected_resource_url: str,
    valid_test_token: str,
    publishable_key: Optional[str] = None,
    timeout: int = 8,
) -> dict[str, Any]:
    """Check a protected read-only resource with no token, an invalid token, and test-user token."""
    endpoint = validate_scope(target_root, protected_resource_url)
    _check_credentials(valid_test_token, publishable_key)
    if not valid_test_token or len(valid_test_token.strip()) < 16:
        raise ValueError("Supply an access token for a dedicated test account (not a password).")
    results = []
    test_headers = [
        ("no_token", _headers(None, publishable_key)),
        ("invalid_token", _headers("pecuvea-invalid-test-token-not-a-real-credential", publishable_key)),
        ("valid_test_user", _headers(valid_test_token, publishable_key)),
    ]
    for label, headers in test_headers:
        if results: time.sleep(MIN_REQUEST_INTERVAL_SECONDS)
        r = _request_get(endpoint, headers, timeout=timeout)
        results.append({"test": label, **r})
    no_token, invalid, valid = results
    findings: list[dict[str, Any]] = []
    valid_works = valid.get("status") is not None and 200 <= valid["status"] < 300 and valid.get("has_structured_data")
    for r in (no_token, invalid):
        if r.get("status") is not None and 200 <= r["status"] < 300 and r.get("has_structured_data"):
            findings.append({
                "severity": "high",
                "title": "Protected-resource authentication boundary may be missing",
                "status": "potential_unauthenticated_access",
                "evidence": f"The {r['test'].replace('_', ' ')} request returned HTTP {r['status']} with a non-empty structured JSON response. The response data itself was not retained.",
                "recommendation": "Confirm this endpoint is intended to be private. If so, enforce authentication server-side / with RLS and repeat with synthetic data. Public endpoints can legitimately return data, so the resource's intended privacy matters.",
                "confidence": "medium",
            })
    if not findings and not valid_works:
        findings.append({
            "severity": "info", "title": "Authentication boundary test inconclusive",
            "status": "inconclusive", "evidence": "The valid test token did not return a non-empty structured JSON response, so this endpoint may require different headers or a different test resource.",
            "recommendation": "Check that the token is an unexpired access token for the dedicated test account, add the project's publishable/anon key if required, and use a read-only endpoint known to return that test account's record.",
            "confidence": "low",
        })
    elif not findings:
        findings.append({
            "severity": "info", "title": "No obvious authentication-boundary failure observed",
            "status": "not_detected_not_proof_of_safety", "evidence": "The valid test user could access structured data while unauthenticated/invalid-token requests did not return non-empty structured data.",
            "recommendation": "Repeat for every sensitive resource and verify server-side authorization/RLS. A single endpoint test cannot prove the entire application is secure.",
            "confidence": "low-to-medium",
        })
    return {
        "target_origin": _origin_label(endpoint), "endpoint_path": urllib.parse.urlsplit(endpoint).path,
        "test_type": "read_only_authentication_boundary", "requests_sent": len(results),
        "response_summaries": [{"test": r["test"], **_summarize_response_for_report(r)} for r in results],
        "findings": findings, "credentials_included_in_report": False, "response_bodies_saved": False,
        "note": "GET-only check. It sends no password attempts and performs no writes. Use only a protected resource and dedicated test account.",
    }


def _origin_label(url: str) -> str:
    p = urllib.parse.urlsplit(url)
    return "{}://{}{}".format(p.scheme, p.hostname, (":" + str(p.port)) if p.port else "")


def idor_authorization_matrix_test(
    target_root: str,
    resource_url_template: str,
    record_id_a: str,
    record_id_b: str,
    token_a: str,
    token_b: str,
    publishable_key: Optional[str] = None,
    timeout: int = 8,
) -> dict[str, Any]:
    """Test cross-account reads for two synthetic records controlled by the user.

    URL template must contain exactly one {id} placeholder. Four GETs are sent: A->A,
    A->B, B->B, B->A. No response bodies or token values are saved.
    """
    if resource_url_template.count("{id}") != 1:
        raise ValueError("The resource URL must contain exactly one {id} placeholder, e.g. https://example.com/api/orders/{id}.")
    if not record_id_a or not record_id_b or record_id_a == record_id_b:
        raise ValueError("Enter two distinct IDs for synthetic records you own/control, one per test account.")
    if any(len(x) > 180 for x in (record_id_a, record_id_b)):
        raise ValueError("Record IDs must be 180 characters or fewer.")
    _check_credentials(token_a, publishable_key); _check_credentials(token_b, publishable_key)
    if not token_a or not token_b or len(token_a.strip()) < 16 or len(token_b.strip()) < 16:
        raise ValueError("Provide access tokens for two dedicated test accounts. Do not use real customer sessions.")
    if token_a.strip() == token_b.strip():
        raise ValueError("Account A and account B must use different test-user access tokens.")
    # Validate the literal URL while preserving the placeholder for safe substitution later.
    sample = resource_url_template.replace("{id}", urllib.parse.quote(record_id_a, safe=""))
    validate_scope(target_root, sample)
    headers_a = _headers(token_a, publishable_key)
    headers_b = _headers(token_b, publishable_key)
    cases = [
        ("account_a_own_record", sample, headers_a, True),
        ("account_a_other_account_record", resource_url_template.replace("{id}", urllib.parse.quote(record_id_b, safe="")), headers_a, False),
        ("account_b_own_record", resource_url_template.replace("{id}", urllib.parse.quote(record_id_b, safe="")), headers_b, True),
        ("account_b_other_account_record", sample, headers_b, False),
    ]
    results=[]
    for i, (label, url, headers, is_own) in enumerate(cases):
        validate_scope(target_root, url)
        if i: time.sleep(MIN_REQUEST_INTERVAL_SECONDS)
        r = _request_get(url, headers, timeout=timeout)
        results.append({"test": label, "own_record": is_own, **r})
    findings=[]
    own_results=[r for r in results if r["own_record"]]
    cross_results=[r for r in results if not r["own_record"]]
    own_data_ok=all(r.get("status") is not None and 200 <= r["status"] < 300 and r.get("has_structured_data") for r in own_results)
    leaked=[r for r in cross_results if r.get("status") is not None and 200 <= r["status"] < 300 and r.get("has_structured_data")]
    if own_data_ok and leaked:
        findings.append({
            "severity": "high", "title": "Potential cross-account object-level authorization failure (IDOR/BOLA)",
            "status": "cross_account_data_returned", "evidence": "At least one test account received non-empty structured JSON for the other test account's record. Response contents and credentials were not retained.",
            "recommendation": "Treat this as a serious lead. Verify the test record ownership, then enforce per-row authorization in the backend/RLS or API handler; never trust client-supplied IDs alone. Retest with the same two test accounts.",
            "confidence": "medium-to-high",
        })
    elif not own_data_ok:
        findings.append({
            "severity": "info", "title": "Authorization matrix inconclusive",
            "status": "own_record_test_not_confirmed", "evidence": "At least one account could not retrieve its expected synthetic record as non-empty structured JSON, so the cross-account comparison is not reliable.",
            "recommendation": "Confirm both IDs belong to the respective test accounts, tokens are valid/unexpired, and headers match the API. Do not substitute real customer IDs.",
            "confidence": "low",
        })
    elif not leaked:
        findings.append({
            "severity": "info", "title": "No cross-account data exposure observed in this matrix",
            "status": "not_detected_not_proof_of_safety", "evidence": "Both own-record requests returned non-empty structured JSON; neither cross-account request returned non-empty structured JSON.",
            "recommendation": "Repeat across every sensitive resource and write path (using synthetic staging records). This GET-only matrix cannot prove all authorization rules are correct.",
            "confidence": "low-to-medium",
        })
    return {
        "target_origin": _origin_label(sample), "endpoint_template": urllib.parse.urlsplit(resource_url_template.replace("{id}", "{id}")).path,
        "test_type": "two_account_idor_authorization_matrix", "requests_sent": len(results),
        "response_summaries": [{"test": r["test"], "own_record": r["own_record"], **_summarize_response_for_report(r)} for r in results],
        "findings": findings, "credentials_included_in_report": False, "response_bodies_saved": False,
        "note": "Four same-origin GET requests only. Use two dedicated test users and synthetic records you control. Never enter real customer IDs or share the report publicly without review.",
    }
