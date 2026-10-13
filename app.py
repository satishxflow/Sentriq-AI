"""Sentriq AI — Next-Generation Application Security & Threat Analysis Platform.

Features:
1. 💉 SQL Injection Engine: Bounded error, Boolean, short-delay, and UNION signal checks; stacked queries and WAF-evasion payloads disabled.
2. 🔐 Authentication Matrix: Multi-layer auth boundaries, JWT decoding & security checks, session cookies.
3. 🚪 Access Control Matrix: Multi-resource horizontal (IDOR/BOLA), vertical privilege escalation, verb tampering.
4. 🗄️ Database Lockdown: API-level schema exposure, permission boundaries, data leak checks & SQL RLS audit.
5. 📊 Execution Dossier: Aggregated evidence, risk scoring (0-100), OWASP/CWE mapping, multi-format export (HTML, MD, JSON).
+ Retains original source code static auditing and passive scanning capabilities.
"""
from __future__ import annotations

import html
import io
import json
import os
import zipfile
import streamlit as st

from scanner import live_passive_scan, scan_source, severity_counts
from engines import (
    advanced_sqli_probe,
    advanced_auth_probe,
    advanced_access_matrix,
    database_lockdown_audit,
    generate_enhanced_rls_sql,
    compile_dossier,
    generate_html_report,
    generate_markdown_report,
    generate_executive_summary,
    generate_remediation_plan,
    generate_json_report,
    build_control_findings,
    simulate_credential_stuffing_defense,
)

st.set_page_config(
    page_title="Sentriq AI — Threat Intelligence & Security Suite",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling
st.markdown("""
<style>
    .metric-card {
        background-color: #0e1117;
        border: 1px solid #262730;
        border-radius: 8px;
        padding: 12px;
        text-align: center;
    }
    .badge-critical { color: #ff4b4b; font-weight: bold; }
    .badge-high { color: #ffa421; font-weight: bold; }
    .badge-medium { color: #ffe312; font-weight: bold; }
    .badge-low { color: #21c354; font-weight: bold; }
    .badge-info { color: #58a6ff; font-weight: bold; }
</style>
""", unsafe_allow_html=True)

# Session State for Scan Results Aggregation
if "all_scan_results" not in st.session_state:
    st.session_state.all_scan_results = []
if "target_profile" not in st.session_state:
    st.session_state.target_profile = {
        "name": "Target Application",
        "url": "",
        "environment": "staging",
        "scope": "Authorized security assessment"
    }

# Sidebar configuration
with st.sidebar:
    st.title("🛡️ Sentriq AI")
    st.caption("Advanced Agentic Application Security Platform")
    st.markdown("---")
    
    st.subheader("🎯 Active Target Profile")
    target_name = st.text_input("Application Name", value=st.session_state.target_profile.get("name", "Target Application"))
    target_url = st.text_input("Target URL / Origin", value=st.session_state.target_profile.get("url", "https://staging.example.com"))
    env_type = st.selectbox("Environment", ["staging", "development", "qa", "production (authorized)"])
    
    st.session_state.target_profile.update({
        "name": target_name,
        "url": target_url,
        "environment": env_type
    })
    
    st.markdown("---")
    st.write(f"**Collected Dossier Modules:** `{len(st.session_state.all_scan_results)}`")
    if st.button("🧹 Clear Collected Findings", use_container_width=True):
        st.session_state.all_scan_results = []
        st.success("Session dossier cleared.")
        st.rerun()

    st.markdown("---")
    st.info("⚠️ **Rules of Engagement**: Only test systems you own or have explicit written permission to assess. All tests use non-destructive, read-only GET/HEAD probes with zero payload mutation.")


st.title("🛡️ Sentriq AI Security Engine")
st.caption("Precision payload probing · Authentication & Access matrix · Data layer audit · Evidence dossiers")

# UI Tabs matching user's requested specification
tabs = st.tabs([
    "💉 SQL Injection Engine",
    "🔐 Authentication Matrix",
    "🚪 Access Control Matrix",
    "🗄️ Database Lockdown",
    "📊 Execution Dossier",
    "📁 Source & Passive Audit"
])


def display_findings_list(findings: list[dict]):
    """Standardized finding renderer."""
    if not findings:
        st.success("No anomalies or vulnerability signals detected.")
        return
    
    counts = severity_counts(findings)
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Critical", counts["critical"])
    c2.metric("High", counts["high"])
    c3.metric("Medium", counts["medium"])
    c4.metric("Low", counts["low"])
    c5.metric("Info", counts["info"])
    
    sev_order = ["critical", "high", "medium", "low", "info"]
    for f in sorted(findings, key=lambda x: sev_order.index(x.get("severity", "info").lower())):
        sev = f.get("severity", "info").upper()
        title = f.get("title", "Untitled Finding")
        with st.expander(f"[{sev}] {title}"):
            cols = st.columns([2, 1])
            with cols[0]:
                st.write("**Verdict:**", f"`{f.get('verdict', 'MANUAL REVIEW')}`")
                st.write("**Status:**", f"`{f.get('status', 'signal')}`")
                if f.get("verification_note"):
                    st.caption(f.get("verification_note"))
                st.write("**Confidence:**", f.get("confidence", "medium").title())
                if f.get("cwe_id"):
                    st.write("**CWE:**", f"`{f.get('cwe_id')}`")
                if f.get("cvss_estimate"):
                    st.write("**CVSS v3.1 Range:**", f"`{f.get('cvss_estimate')}`")
            with cols[1]:
                if f.get("attack_vector"):
                    st.write("**Vector:**", f"`{f.get('attack_vector')}`")
                if f.get("payload_type"):
                    st.write("**Payload Type:**", f"`{f.get('payload_type')}`")

            st.markdown("**Evidence:**")
            st.code(f.get("evidence", "No evidence snippet provided."))
            st.markdown("**Remediation:**")
            st.info(f.get("recommendation", "Review secure coding standards."))


# ==============================================================================
# TAB 1: SQL INJECTION ENGINE
# ==============================================================================
with tabs[0]:
    st.subheader("💉 SQL Injection Engine")
    st.markdown("Bounded error-based, Boolean differential, short-delay, and UNION signal checks. Stacked queries and WAF-evasion payloads are disabled. Run only against authorized staging endpoints with synthetic data.")
    
    with st.form("sqli_form"):
        col1, col2 = st.columns(2)
        with col1:
            sqli_root = st.text_input("Target Root Origin (HTTPS)", value=st.session_state.target_profile.get("url", "https://staging.example.com"))
            sqli_endpoint = st.text_input("Target Endpoint URL", placeholder="https://staging.example.com/api/products?search=item")
            sqli_param = st.text_input("Parameter to Probe", value="search")
            sqli_base = st.text_input("Baseline Valid Value", value="chair")
        with col2:
            sqli_context = st.selectbox("Injection Context", ["string", "numeric", "like", "orderby", "json"])
            probe_types = st.multiselect(
                "Vectors to Deploy",
                ["error_based", "boolean_blind", "time_based", "union_based"],
                default=["error_based", "boolean_blind"]
            )
            sqli_waf = False  # WAF-evasion payloads are disabled in v5
            sqli_max_req = st.slider("Maximum Requests Budget", 3, 10, 8)
        
        col3, col4 = st.columns(2)
        with col3:
            sqli_token = st.text_input("Test User Bearer Token (Optional)", type="password")
        with col4:
            sqli_key = st.text_input("Publishable / Anon API Key (Optional)", type="password")
            
        sqli_ack = st.checkbox("I verify this endpoint belongs to my authorized test environment and contains synthetic data.")
        sqli_phrase = st.text_input("Type RUN AUTHORIZED TESTS to confirm scope")
        sqli_submit = st.form_submit_button("🚀 Deploy SQL Injection Probes", type="primary")

    if sqli_submit:
        if not sqli_ack or sqli_phrase.strip() != "RUN AUTHORIZED TESTS":
            st.error("Confirm authorization and type RUN AUTHORIZED TESTS before initiating active probes.")
        elif not sqli_endpoint:
            st.error("Please enter a valid target endpoint URL.")
        else:
            with st.spinner("Probing data-layer defenses..."):
                try:
                    res = advanced_sqli_probe(
                        target_root=sqli_root.strip(),
                        endpoint_url=sqli_endpoint.strip(),
                        parameter=sqli_param.strip(),
                        base_value=sqli_base.strip(),
                        probe_types=probe_types or None,
                        context=sqli_context,
                        bearer_token=sqli_token.strip() or None,
                        publishable_key=sqli_key.strip() or None,
                        waf_evasion=sqli_waf,
                        max_requests=sqli_max_req
                    )
                    st.session_state.all_scan_results.append(res)
                    st.success(f"Probing complete! Sent {res['requests_sent']} request(s).")
                    
                    st.write("### 📋 Findings & Diagnostics")
                    display_findings_list(res.get("findings", []))
                    
                    if res.get("response_summaries"):
                        with st.expander("🔍 View Request/Response Telemetry (Sanitized)"):
                            st.dataframe(res["response_summaries"], use_container_width=True)
                except Exception as e:
                    st.error(f"Execution Error: {e}")


    st.markdown("---")
    st.subheader("🧯 Neutralization playbook")
    st.markdown("Detection is not remediation. Prefer parameterized queries and allowlists for identifiers; do not attempt to sanitize SQL by deleting quote characters or blacklisting keywords.")
    with st.expander("Python · SQLite / PostgreSQL examples"):
        st.code("""# SQLite: bind values separately from SQL syntax
cur.execute("SELECT id, name FROM products WHERE name = ?", (search_term,))

# PostgreSQL with psycopg: use %s placeholders
cur.execute("SELECT id, name FROM products WHERE name = %s", (search_term,))
""", language="python")
    with st.expander("Node.js · PostgreSQL example"):
        st.code("""const result = await pool.query(
  'SELECT id, name FROM products WHERE name = $1',
  [searchTerm]
);
""", language="javascript")
    with st.expander("Supabase JavaScript client example"):
        st.code("""// Prefer the query builder; do not concatenate user input into raw SQL.
const { data, error } = await supabase
  .from('products')
  .select('id, name')
  .eq('name', searchTerm);
""", language="javascript")
    st.caption("For dynamic column names or sort directions, use a strict server-side allowlist; bind parameters cannot safely replace SQL identifiers.")


# ==============================================================================
# TAB 2: AUTHENTICATION MATRIX
# ==============================================================================
with tabs[1]:
    st.subheader("🔐 Authentication Matrix")
    st.markdown("Exposes authentication boundaries across missing credentials, invalid tokens, empty/null bearers, token in query strings, session cookie security flags, and offline cryptographic JWT audits.")
    
    with st.form("auth_form"):
        auth_root = st.text_input("Target Origin", value=st.session_state.target_profile.get("url", "https://staging.example.com"))
        auth_endpoints_input = st.text_area("Protected Endpoints (one per line)", value=f"{st.session_state.target_profile.get('url', 'https://staging.example.com')}/api/user/profile")
        
        c1, c2 = st.columns(2)
        with c1:
            auth_token = st.text_input("Valid Test-Account Access Token (Required)", type="password")
        with c2:
            auth_apikey = st.text_input("Publishable / Anon Key (Optional)", type="password")
            
        col_c, col_d = st.columns(2)
        with col_c:
            auth_jwt_eval = st.checkbox("Offline JWT Claims & Security Audit", value=True)
        with col_d:
            auth_cookie_eval = st.checkbox("Analyze Cookie & Session Security Flags", value=True)
            
        auth_ack = st.checkbox("I authorize testing on these protected endpoints using my designated test account.")
        auth_phrase = st.text_input("Type RUN AUTHORIZED TESTS to confirm scope", key="auth_scope_phrase")
        auth_submit = st.form_submit_button("🛡️ Run Authentication Matrix", type="primary")

    if auth_submit:
        if not auth_ack or auth_phrase.strip() != "RUN AUTHORIZED TESTS":
            st.error("Confirm authorization and type RUN AUTHORIZED TESTS.")
        elif not auth_token:
            st.error("A valid test-user access token is required to establish baseline authentication.")
        else:
            endpoints = [e.strip() for e in auth_endpoints_input.splitlines() if e.strip()]
            with st.spinner("Analyzing authentication defenses & tokens..."):
                try:
                    res = advanced_auth_probe(
                        target_root=auth_root.strip(),
                        protected_endpoints=endpoints,
                        valid_test_token=auth_token.strip(),
                        publishable_key=auth_apikey.strip() or None,
                        analyze_jwt=auth_jwt_eval,
                        check_session_security=auth_cookie_eval
                    )
                    st.session_state.all_scan_results.append(res)
                    st.success(f"Audit completed across {len(endpoints)} endpoint(s).")
                    
                    display_findings_list(res.get("findings", []))
                    
                    if res.get("response_summaries"):
                        with st.expander("🔍 Response Summaries"):
                            st.dataframe(res["response_summaries"], use_container_width=True)
                except Exception as e:
                    st.error(f"Auth Matrix Error: {e}")


    st.markdown("---")
    st.subheader("🧭 Defensive control verification (manual / no network traffic)")
    st.caption("Use this checklist for controls that should not be tested by brute force or session theft. These entries are operator-attested, not independently verified by Sentriq.")
    with st.form("auth_defense_checklist"):
        c1, c2 = st.columns(2)
        with c1:
            rate_limit_result = st.selectbox("Login rate limiting / lockout", ["Not tested", "Verified", "Failed"], key="ctl_rate_limit")
            stuffing_result = st.selectbox("Credential-stuffing resistance", ["Not tested", "Verified", "Failed"], key="ctl_stuffing")
            mfa_result = st.selectbox("MFA / passkey for sensitive access", ["Not tested", "Verified", "Failed"], key="ctl_mfa")
            jwt_result = st.selectbox("JWT signature + issuer/audience/expiry checks", ["Not tested", "Verified", "Failed"], key="ctl_jwt")
        with c2:
            rotation_result = st.selectbox("Session rotation after login/privilege change", ["Not tested", "Verified", "Failed"], key="ctl_rotation")
            revoke_result = st.selectbox("Session revocation after logout/password change", ["Not tested", "Verified", "Failed"], key="ctl_revoke")
            cookie_result = st.selectbox("Secure / HttpOnly / SameSite cookie flags", ["Not tested", "Verified", "Failed"], key="ctl_cookie")
        ctl_submit = st.form_submit_button("Add Control Checklist to Dossier")
    if ctl_submit:
        mapping = {"Verified": "verified", "Failed": "failed", "Not tested": "not_tested"}
        ctl_results = {
            "rate_limiting": mapping[rate_limit_result],
            "credential_stuffing": mapping[stuffing_result],
            "mfa": mapping[mfa_result],
            "jwt_validation": mapping[jwt_result],
            "session_rotation": mapping[rotation_result],
            "session_revocation": mapping[revoke_result],
            "cookie_flags": mapping[cookie_result],
        }
        checklist = build_control_findings(ctl_results)
        st.session_state.all_scan_results.append(checklist)
        st.success("Self-attested control checklist added. Results are clearly labeled as operator-reported.")


    st.markdown("---")
    st.subheader("🧪 Offline credential-stuffing defense simulator")
    st.caption("Synthetic model only: this does not contact your website, use passwords, or send login attempts. It demonstrates how simple per-account and per-source thresholds behave; it is not proof that a live identity provider is protected.")
    with st.form("offline_stuffing_simulation"):
        sim_c1, sim_c2 = st.columns(2)
        with sim_c1:
            sim_attempts = st.slider("Synthetic attempts", 10, 200, 60, 10)
            sim_accounts = st.slider("Synthetic accounts", 1, 100, 30, 1)
            sim_sources = st.slider("Synthetic sources", 1, 50, 10, 1)
        with sim_c2:
            sim_account_limit = st.slider("Allowed attempts per account", 1, 20, 5, 1)
            sim_source_limit = st.slider("Allowed attempts per source", 1, 30, 10, 1)
        sim_submit = st.form_submit_button("Run Offline Simulation")
    if sim_submit:
        sim = simulate_credential_stuffing_defense(sim_attempts, sim_accounts, sim_sources, sim_account_limit, sim_source_limit)
        st.session_state.all_scan_results.append(sim)
        sm1, sm2, sm3 = st.columns(3)
        sm1.metric("Simulated", sim["attempts_simulated"])
        sm2.metric("Allowed", sim["allowed"])
        sm3.metric("Blocked", sim["blocked"])
        st.info(sim["note"])
        display_findings_list(sim["findings"])


# ==============================================================================
# TAB 3: ACCESS CONTROL MATRIX
# ==============================================================================
with tabs[2]:
    st.subheader("🚪 Access Control Matrix")
    st.markdown("Hunts for Horizontal Privilege Escalation (IDOR / BOLA) across user accounts and Vertical Privilege Escalation onto admin endpoints.")
    
    with st.form("access_form"):
        acc_root = st.text_input("Target Origin", value=st.session_state.target_profile.get("url", "https://staging.example.com"))
        
        st.write("##### 1. Horizontal IDOR / BOLA Resource Matrix")
        acc_template = st.text_input("Resource URL Template (use `{id}` placeholder)", value=f"{st.session_state.target_profile.get('url', 'https://staging.example.com')}/api/orders/{{id}}")
        
        ca, cb = st.columns(2)
        with ca:
            acc_id_a = st.text_input("Record ID owned by User A", value="1001")
            acc_tok_a = st.text_input("User A Access Token", type="password")
        with cb:
            acc_id_b = st.text_input("Record ID owned by User B", value="1002")
            acc_tok_b = st.text_input("User B Access Token", type="password")
            
        st.write("##### 2. Vertical Privilege Escalation Probing")
        admin_routes = st.text_area("Admin-Restricted Endpoints (Optional, one per line)", value=f"{st.session_state.target_profile.get('url', 'https://staging.example.com')}/api/admin/users")
        
        acc_method_confusion = st.checkbox("Check HTTP Method Confusion (HEAD Verb Tampering)", value=True)
        acc_ack = st.checkbox("I confirm both accounts and records are synthetic test artifacts under my control.")
        acc_phrase = st.text_input("Type RUN AUTHORIZED TESTS to confirm scope", key="access_scope_phrase")
        acc_submit = st.form_submit_button("⚖️ Run Authorization Matrix", type="primary")

    if acc_submit:
        if not acc_ack or acc_phrase.strip() != "RUN AUTHORIZED TESTS":
            st.error("Confirm synthetic test data and type RUN AUTHORIZED TESTS.")
        elif not acc_tok_a or not acc_tok_b:
            st.error("Two distinct test-user tokens are required to evaluate cross-account boundaries.")
        else:
            resource_specs = [{
                "url_template": acc_template.strip(),
                "id_a": acc_id_a.strip(),
                "id_b": acc_id_b.strip(),
                "label": "primary_resource"
            }]
            adm_list = [r.strip() for r in admin_routes.splitlines() if r.strip()]
            
            with st.spinner("Testing object-level and role-level boundaries..."):
                try:
                    res = advanced_access_matrix(
                        target_root=acc_root.strip(),
                        resource_templates=resource_specs,
                        token_a=acc_tok_a.strip(),
                        token_b=acc_tok_b.strip(),
                        admin_endpoints=adm_list,
                        check_method_confusion=acc_method_confusion
                    )
                    st.session_state.all_scan_results.append(res)
                    st.success("Authorization matrix assessment completed.")
                    
                    display_findings_list(res.get("findings", []))
                    
                    if res.get("response_summaries"):
                        with st.expander("🔍 Matrix Transcripts"):
                            st.dataframe(res["response_summaries"], use_container_width=True)
                except Exception as e:
                    st.error(f"Access Matrix Error: {e}")


# ==============================================================================
# TAB 4: DATABASE LOCKDOWN
# ==============================================================================
with tabs[3]:
    st.subheader("🗄️ Database Lockdown & API Permissions")
    st.markdown("Audits database exposures through REST/GraphQL/Supabase gateways: PostgREST schema disclosures, open buckets, over-privileged fields, and generates hardened PostgreSQL RLS SQL.")
    
    with st.form("db_form"):
        db_root = st.text_input("Target Root Origin", value=st.session_state.target_profile.get("url", "https://staging.example.com"))
        db_key = st.text_input("Publishable / Anon Key (Optional)", type="password")
        db_token = st.text_input("Test User Token (Optional)", type="password")
        
        c1, c2 = st.columns(2)
        with c1:
            db_chk_supa = st.checkbox("Check PostgREST & Supabase-specific Gateways", value=True)
        with c2:
            db_chk_gql = st.checkbox("Check GraphQL Introspection Endpoints", value=True)
            
        custom_tables = st.text_input("Specific Tables to Check (comma-separated, optional)", placeholder="users, profiles, invoices, products")
        db_ack = st.checkbox("I authorize database exposure and gateway probing on this target.")
        db_phrase = st.text_input("Type RUN AUTHORIZED TESTS to confirm scope", key="db_scope_phrase")
        db_submit = st.form_submit_button("🔍 Execute Database Lockdown Audit", type="primary")

    if db_submit:
        if not db_ack or db_phrase.strip() != "RUN AUTHORIZED TESTS":
            st.error("Confirm authorization and type RUN AUTHORIZED TESTS.")
        else:
            tables = [t.strip() for t in custom_tables.split(",") if t.strip()] if custom_tables else None
            with st.spinner("Probing schema exposures and permission gates..."):
                try:
                    res = database_lockdown_audit(
                        target_root=db_root.strip(),
                        publishable_key=db_key.strip() or None,
                        test_token=db_token.strip() or None,
                        known_tables=tables,
                        check_supabase=db_chk_supa,
                        check_graphql=db_chk_gql
                    )
                    st.session_state.all_scan_results.append(res)
                    st.success("Database lockdown audit finished.")
                    
                    display_findings_list(res.get("findings", []))
                except Exception as e:
                    st.error(f"Database Audit Error: {e}")

    st.markdown("---")
    st.subheader("🛠️ Hardened PostgreSQL / Supabase RLS Verification Script")
    st.markdown("Run this comprehensive 10-point audit script directly inside your database SQL editor as project owner.")
    sql_script = generate_enhanced_rls_sql()
    st.code(sql_script, language="sql")
    st.download_button(
        "📥 Download Enhanced RLS Audit SQL",
        sql_script,
        file_name="sentriq_enhanced_rls_audit.sql",
        mime="text/plain"
    )


# ==============================================================================
# TAB 5: EXECUTION DOSSIER
# ==============================================================================
with tabs[4]:
    st.subheader("📊 Execution Dossier & Strike Report")
    st.markdown("Compiles all module telemetry into an undeniable, evidence-backed security dossier with risk scoring (0-100), OWASP/CWE correlations, attack narrative chains, and phased remediation roadmaps.")
    
    if not st.session_state.all_scan_results:
        st.info("No active module findings have been recorded yet in this session. Execute any of the test modules above (SQL Injection, Auth, Access, Database) to compile the final dossier.")
    else:
        dossier = compile_dossier(
            scan_results=st.session_state.all_scan_results,
            target_info=st.session_state.target_profile
        )
        
        # Risk Posture Cards
        risk_score = dossier.get("risk_scoring", {}).get("overall_score", 0.0)
        posture = dossier.get("risk_scoring", {}).get("posture_tier", "Unknown")
        
        col_r1, col_r2, col_r3 = st.columns([1, 1, 2])
        col_r1.metric("Overall Risk Score", f"{risk_score}/100")
        col_r2.metric("Posture Tier", posture)
        with col_r3:
            stats = dossier.get("finding_statistics", {}).get("counts_by_severity", {})
            st.write(f"**Total Findings:** `{dossier.get('finding_statistics', {}).get('total_findings', 0)}` "
                     f"(Critical: `{stats.get('critical', 0)}`, High: `{stats.get('high', 0)}`, "
                     f"Medium: `{stats.get('medium', 0)}`, Low: `{stats.get('low', 0)}`)")
            st.progress(min(1.0, max(0.0, risk_score / 100.0)))

        # Category Breakdown
        st.write("##### 📈 Risk Score by Vector")
        cat_scores = dossier.get("risk_scoring", {}).get("category_scores", {})
        cc1, cc2, cc3, cc4 = st.columns(4)
        cc1.metric("💉 Injection", f"{cat_scores.get('injection', 0)}/100")
        cc2.metric("🔐 Authentication", f"{cat_scores.get('authentication', 0)}/100")
        cc3.metric("🚪 Authorization", f"{cat_scores.get('authorization', 0)}/100")
        cc4.metric("🗄️ Data Exposure", f"{cat_scores.get('data_exposure', 0)}/100")

        # Correlated Attack Chains
        chains = dossier.get("evidence_chains", [])
        if chains:
            st.write("##### ⚡ Correlated Compound Attack Chains")
            for ch in chains:
                with st.expander(f"⚠️ {ch.get('title')} ({ch.get('severity', 'high').upper()})"):
                    st.write(f"**Impact:** {ch.get('narrative')}")
                    st.write(f"**Remediation Vector:** {ch.get('remediation')}")

        st.markdown("---")
        st.write("##### 📥 Export Dossier in Multiple Formats")
        
        btn_c1, btn_c2, btn_c3, btn_c4 = st.columns(4)
        
        with btn_c1:
            html_rep = generate_html_report(dossier)
            st.download_button(
                "🌐 Download HTML Report",
                html_rep,
                file_name="sentriq-security-dossier.html",
                mime="text/html",
                use_container_width=True
            )
        with btn_c2:
            md_rep = generate_markdown_report(dossier)
            st.download_button(
                "📝 Download Markdown Dossier",
                md_rep,
                file_name="sentriq-security-dossier.md",
                mime="text/markdown",
                use_container_width=True
            )
        with btn_c3:
            exec_rep = generate_executive_summary(dossier)
            st.download_button(
                "👔 Download Executive Brief",
                exec_rep,
                file_name="sentriq-executive-brief.md",
                mime="text/markdown",
                use_container_width=True
            )
        with btn_c4:
            rem_plan = generate_remediation_plan(dossier)
            st.download_button(
                "🛠️ Download Remediation Plan",
                rem_plan,
                file_name="sentriq-remediation-plan.md",
                mime="text/markdown",
                use_container_width=True
            )

        st.markdown("---")
        st.write("### 📜 Consolidated Vulnerability Registry")
        display_findings_list(dossier.get("findings", []))


# ==============================================================================
# TAB 6: SOURCE & PASSIVE AUDIT (Classic Capability Preservation)
# ==============================================================================
with tabs[5]:
    st.subheader("📁 Static Source Audit & Passive Crawler")
    st.markdown("Audit client-side source bundles (HTML/JS/ZIP) and inspect live HTTPS headers.")
    
    subtab1, subtab2 = st.tabs(["📁 Source Code Audit", "🌐 Passive HTTPS Scan"])
    
    with subtab1:
        up = st.file_uploader("Upload HTML, JS, or ZIP bundle", type=["html", "htm", "js", "mjs", "zip"])
        if up and st.button("Run Source Analysis", type="primary"):
            reports = []
            try:
                if up.name.lower().endswith(".zip"):
                    with zipfile.ZipFile(io.BytesIO(up.getvalue())) as z:
                        candidates = [i for i in z.infolist() if not i.is_dir() and i.file_size <= 5_000_000 and i.filename.lower().endswith((".html", ".htm", ".js", ".mjs")) and ".." not in i.filename]
                        if len(candidates) > 150:
                            st.warning("Analysis truncated to first 150 files.")
                            candidates = candidates[:150]
                        for item in candidates:
                            try:
                                reports.append(scan_source(z.read(item).decode("utf-8", "replace"), item.filename))
                            except Exception:
                                pass
                else:
                    reports = [scan_source(up.getvalue().decode("utf-8", "replace"), up.name)]
                    
                if not reports:
                    st.error("No readable source files found.")
                else:
                    for r in reports:
                        st.subheader(r["filename"])
                        display_findings_list(r.get("findings", []))
                        st.session_state.all_scan_results.append(r)
            except zipfile.BadZipFile:
                st.error("Invalid ZIP archive.")
                
    with subtab2:
        passive_url = st.text_input("Target URL for Passive Inspection", placeholder="https://example.com")
        pass_confirm = st.checkbox("I own or am authorized to passively inspect this site.")
        pass_phrase = st.text_input("Type PASSIVE SCAN to proceed")
        max_p = st.slider("Max Pages to Crawl (GET only)", 1, 25, 8)
        
        if st.button("Start Passive Scan", type="primary"):
            if not pass_confirm or pass_phrase.strip() != "PASSIVE SCAN":
                st.error("Confirmation checklist incomplete.")
            else:
                with st.spinner("Reviewing security headers & crawling..."):
                    try:
                        r = live_passive_scan(passive_url.strip(), max_pages=max_p)
                        st.session_state.all_scan_results.append(r)
                        st.metric("Pages Checked", r.get("pages_checked", 0))
                        st.dataframe(r.get("pages", []), use_container_width=True)
                        display_findings_list(r.get("findings", []))
                    except Exception as e:
                        st.error(str(e))
