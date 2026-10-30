# -*- coding: utf-8 -*-
"""
Comprehensive Regression, Security, Validation, OAuth 2.1 PKCE, SLA, and
Evaluation Verification Suite for Sewa Setu.
"""

import base64
import hashlib
import importlib.util
import json
import os
import random
import secrets
import sys
import time
from datetime import date, datetime, timedelta
from urllib.parse import parse_qs, urlparse

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PYLIBS_DIR = os.path.join(ROOT_DIR, ".pylibs")
APP_DIR = os.path.join(ROOT_DIR, "app")
for p in (APP_DIR, PYLIBS_DIR):
    if os.path.isdir(p) and p not in sys.path:
        sys.path.insert(0, p)

import requests
import app as portal
import oauth

BASE_URL = os.environ.get("APP_BASE_URL", "http://localhost:3000").rstrip("/")
SAMPLE_PDF_B64 = base64.b64encode(b"%PDF-1.4 Valid Age Proof Document").decode("ascii")


def _cleanup_test_mobile(mobile):
    conn = portal.get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, doc_path FROM applications WHERE mobile = %s", (mobile,))
    for app_id, doc_path in cur.fetchall():
        cur.execute("DELETE FROM audit_log WHERE application_id = %s", (app_id,))
        if doc_path and os.path.exists(doc_path):
            try:
                os.remove(doc_path)
            except OSError:
                pass
    cur.execute("DELETE FROM applications WHERE mobile = %s", (mobile,))
    cur.execute("DELETE FROM portal_users WHERE mobile = %s", (mobile,))
    cur.execute("DELETE FROM otps WHERE mobile = %s", (mobile,))
    conn.commit()
    cur.close()
    conn.close()


def test_mcp_citizen_endpoint_and_validation():
    print("=== 1. Testing Citizen MCP Server & Authoritative Validation (/mcp/citizen) ===")

    # 1a. Discovery & Dynamic External URL Resolution
    r_info = requests.get(
        f"{BASE_URL}/mcp/citizen",
        headers={
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Host": "sewasetu-ext.example.gov.in",
        },
        timeout=5,
    )
    assert r_info.status_code == 200
    info = r_info.json()
    assert "Sewa Setu Citizen MCP Server" in info.get("service")
    assert info["endpoints"]["post"] == "https://sewasetu-ext.example.gov.in/mcp/citizen"
    print("✓ GET /mcp/citizen discovery & X-Forwarded-Host external URL resolution verified.")

    # 1b. SSE transport endpoint event
    r_sse = requests.get(
        f"{BASE_URL}/mcp/citizen",
        headers={"Accept": "text/event-stream", "X-Forwarded-Proto": "https", "X-Forwarded-Host": "sewasetu-ext.example.gov.in"},
        stream=True,
        timeout=5,
    )
    assert r_sse.status_code == 200
    lines_iter = r_sse.iter_lines(chunk_size=1, decode_unicode=True)
    first_chunk = next(lines_iter)
    second_chunk = next(lines_iter)
    assert "event: endpoint" in first_chunk
    assert "https://sewasetu-ext.example.gov.in/mcp/citizen/messages" in second_chunk
    r_sse.close()
    print("✓ GET /mcp/citizen SSE transport emits external endpoint event.")

    # 1c. JSON-RPC Initialize & tools/list
    r_init = requests.post(
        f"{BASE_URL}/mcp/citizen",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "audit-test-client", "version": "1.0.0"},
            },
        },
        timeout=5,
    )
    assert r_init.status_code == 200
    assert r_init.json()["result"]["protocolVersion"] == "2024-11-05"

    r_list = requests.post(
        f"{BASE_URL}/mcp/citizen",
        json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        timeout=5,
    )
    tools = [t["name"] for t in r_list.json()["result"]["tools"]]
    assert set(tools) == {"get_scheme_rules", "check_application_requirements", "submit_application", "get_application_status"}
    print(f"✓ Citizen MCP initialize and tools/list verified: {tools}")

    # 1d. Validation checks on submit_application (Missing document, Bad extension, >5MB size)
    test_mobile = "9999000201"
    _cleanup_test_mobile(test_mobile)
    token_citizen, _ = oauth.mint_access_token(
        f"citizen:{test_mobile}", "citizen", "citizen", oauth.ISSUER, "test-client"
    )
    auth_headers = {"Authorization": f"Bearer {token_citizen}"}

    base_args = {
        "applicant_name": "Audit Test Citizen",
        "dob": "10/02/1955",
        "gender": "Male",
        "marital_status": "Married",
        "village": "Disangmukh",
        "block": "Sonari",
        "bank_account": "38472910485",
        "ifsc": "SBIN0003077",
    }

    # Missing document_base64 must fail (Defect 1 regression test)
    r_nodoc = requests.post(
        f"{BASE_URL}/mcp/citizen",
        json={"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "submit_application", "arguments": base_args}},
        headers=auth_headers,
        timeout=5,
    )
    res_nodoc = r_nodoc.json()["result"]
    assert res_nodoc["isError"] is True
    assert "age proof document is required" in res_nodoc["content"][0]["text"]
    print("✓ Missing document_base64 strictly rejected with 'age proof document is required'.")

    # Disallowed file extension (.exe) must fail
    bad_ext_args = dict(base_args, document_name="malware.exe", document_base64=SAMPLE_PDF_B64)
    r_badext = requests.post(
        f"{BASE_URL}/mcp/citizen",
        json={"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "submit_application", "arguments": bad_ext_args}},
        headers=auth_headers,
        timeout=5,
    )
    res_badext = r_badext.json()["result"]
    assert res_badext["isError"] is True
    assert "JPG, PNG, or PDF" in res_badext["content"][0]["text"]
    print("✓ Disallowed file extension (.exe) strictly rejected.")

    # Oversized document (> 5 MB) must fail
    oversized_b64 = base64.b64encode(b"A" * (5 * 1024 * 1024 + 1024)).decode("ascii")
    oversized_args = dict(base_args, document_name="large.pdf", document_base64=oversized_b64)
    r_oversized = requests.post(
        f"{BASE_URL}/mcp/citizen",
        json={"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "submit_application", "arguments": oversized_args}},
        headers=auth_headers,
        timeout=10,
    )
    res_oversized = r_oversized.json()["result"]
    assert res_oversized["isError"] is True
    assert "5 MB limit" in res_oversized["content"][0]["text"]
    print("✓ Oversized document (> 5 MB) strictly rejected.")

    # 1e. Valid submission
    valid_args = dict(base_args, document_name="voter_id.pdf", document_base64=SAMPLE_PDF_B64)
    r_sub = requests.post(
        f"{BASE_URL}/mcp/citizen",
        json={"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "submit_application", "arguments": valid_args}},
        headers=auth_headers,
        timeout=5,
    )
    res_sub = r_sub.json()["result"]
    assert res_sub["isError"] is False
    sub_data = json.loads(res_sub["content"][0]["text"])
    assert sub_data["success"] is True
    app_no = sub_data["application_no"]
    app_id = sub_data["application_id"]
    print(f"✓ Valid citizen application submitted: {app_no} (ID: {app_id}).")

    return app_id, app_no, test_mobile, token_citizen


def test_jwt_security_and_officer_mcp(app_id, app_no, token_citizen):
    print("\n=== 2. Testing OAuth/JWT Security, Revocation & Officer MCP (/mcp/officer) ===")

    list_call = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "list_pending_applications", "arguments": {}}}

    # 2a. Missing token -> -32001
    r_unauth = requests.post(f"{BASE_URL}/mcp/officer", json=list_call, timeout=5)
    assert r_unauth.json()["error"]["code"] == -32001
    print("✓ Unauthenticated request rejected (-32001).")

    # 2b. Citizen token on Officer endpoint -> -32002
    r_cit = requests.post(
        f"{BASE_URL}/mcp/officer",
        json=list_call,
        headers={"Authorization": f"Bearer {token_citizen}"},
        timeout=5,
    )
    assert r_cit.json()["error"]["code"] == -32002
    print("✓ Citizen token on Officer MCP rejected (-32002).")

    # 2c. Token with foreign audience -> -32001 (Defect 2 regression test)
    bad_aud_token, _ = oauth.mint_access_token(
        "officer:admin", "officer", "officer", "https://foreign-service.example.com", "bad-client"
    )
    r_badaud = requests.post(
        f"{BASE_URL}/mcp/officer",
        json=list_call,
        headers={"Authorization": f"Bearer {bad_aud_token}"},
        timeout=5,
    )
    assert r_badaud.json()["error"]["code"] == -32001
    assert "Invalid token audience" in r_badaud.json()["error"]["message"]
    print("✓ Foreign-audience JWT strictly rejected (-32001).")

    # 2d. Expired token -> -32001
    expired_token, _ = oauth.mint_access_token(
        "officer:admin", "officer", "officer", oauth.ISSUER, "exp-client", ttl=-60
    )
    r_exp = requests.post(
        f"{BASE_URL}/mcp/officer",
        json=list_call,
        headers={"Authorization": f"Bearer {expired_token}"},
        timeout=5,
    )
    assert r_exp.json()["error"]["code"] == -32001
    print("✓ Expired JWT strictly rejected (-32001).")

    # 2e. Program token issuance, usage, and revocation (Defect 3 regression test)
    prog_token, prog_claims = oauth.mint_access_token(
        "officer:admin", "officer", "officer", oauth.ISSUER, "admin-issued", ttl=86400, kind="program"
    )
    conn = portal.get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO oauth_program_tokens (jti, label, subject, audience, issued_by, created_at, expires_at) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s)",
        (prog_claims["jti"], "test-prog", "officer:admin", oauth.ISSUER, "admin", datetime.now(), datetime.now() + timedelta(days=1)),
    )
    conn.commit()
    cur.close(); conn.close()

    # Works before revocation
    r_prog_ok = requests.post(
        f"{BASE_URL}/mcp/officer",
        json=list_call,
        headers={"Authorization": f"Bearer {prog_token}"},
        timeout=5,
    )
    assert "result" in r_prog_ok.json()

    # Revoke via /oauth/revoke
    r_rev = requests.post(f"{BASE_URL}/oauth/revoke", data={"token": prog_token}, timeout=5)
    assert r_rev.status_code == 200

    # Rejected after revocation
    r_prog_revoked = requests.post(
        f"{BASE_URL}/mcp/officer",
        json=list_call,
        headers={"Authorization": f"Bearer {prog_token}"},
        timeout=5,
    )
    assert r_prog_revoked.json()["error"]["code"] == -32001
    assert "revoked" in r_prog_revoked.json()["error"]["message"].lower()
    print("✓ Long-lived program token revocation enforced across /oauth/revoke and /mcp/officer.")

    # 2f. Officer get_application_details sanitizes file path (Defect 7 regression test)
    token_officer, _ = oauth.mint_access_token(
        "officer:admin", "officer", "officer", oauth.ISSUER, "officer-client"
    )
    r_det = requests.post(
        f"{BASE_URL}/mcp/officer",
        json={"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "get_application_details", "arguments": {"application_id": app_id}}},
        headers={"Authorization": f"Bearer {token_officer}"},
        timeout=5,
    )
    det_data = json.loads(r_det.json()["result"]["content"][0]["text"])
    assert "document_path" not in det_data
    assert det_data.get("document_filename", "").endswith("voter_id.pdf")
    print("✓ Officer get_application_details exposes sanitized document_filename without raw server paths.")

    # 2g. Officer approves application
    r_app = requests.post(
        f"{BASE_URL}/mcp/officer",
        json={
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "approve_application", "arguments": {"application_id": app_id, "note": "Verified in audit test"}},
        },
        headers={"Authorization": f"Bearer {token_officer}"},
        timeout=5,
    )
    app_data = json.loads(r_app.json()["result"]["content"][0]["text"])
    assert app_data["status"] == "APPROVED"
    print(f"✓ Officer approve_application succeeded for {app_no}.")


def test_oauth_pkce_external_client_flow():
    print("\n=== 3. Testing End-to-End OAuth 2.1 DCR + PKCE S256 External Client Flow ===")
    s = requests.Session()

    # 3a. Dynamic Client Registration (/oauth/register)
    redirect_uri = "http://localhost:54321/callback"
    r_reg = s.post(
        f"{BASE_URL}/oauth/register",
        json={
            "client_name": "Claude Code External MCP Client",
            "redirect_uris": [redirect_uri],
            "token_endpoint_auth_method": "none",
        },
        timeout=5,
    )
    assert r_reg.status_code == 201
    client_id = r_reg.json()["client_id"]

    # 3b. PKCE S256 challenge
    code_verifier = secrets.token_urlsafe(32)
    code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")

    # 3c. /oauth/authorize -> redirects to /oauth/login?rid=...
    r_auth = s.get(
        f"{BASE_URL}/oauth/authorize",
        params={
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "citizen",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": "xyz123",
        },
        allow_redirects=True,
        timeout=5,
    )
    assert r_auth.status_code == 200
    rid = parse_qs(urlparse(r_auth.url).query)["rid"][0]

    # 3d. Citizen login step 1: request OTP
    pkce_mobile = "9999000202"
    _cleanup_test_mobile(pkce_mobile)
    s.post(f"{BASE_URL}/oauth/login?rid={rid}", data={"mobile": pkce_mobile}, timeout=5)

    # Read OTP from DB
    conn = portal.get_db()
    cur = conn.cursor()
    cur.execute("SELECT code FROM otps WHERE mobile = %s ORDER BY id DESC LIMIT 1", (pkce_mobile,))
    otp_code = cur.fetchone()[0]
    cur.close(); conn.close()

    # 3e. Citizen login step 2: submit OTP -> redirects to /oauth/consent
    r_login = s.post(f"{BASE_URL}/oauth/login?rid={rid}", data={"otp": otp_code}, allow_redirects=True, timeout=5)
    assert "/oauth/consent" in r_login.url

    # 3f. Citizen approves consent -> 302 redirect to redirect_uri with code
    r_consent = s.post(f"{BASE_URL}/oauth/consent?rid={rid}", data={"decision": "allow"}, allow_redirects=False, timeout=5)
    assert r_consent.status_code == 302
    loc = r_consent.headers["Location"]
    auth_code = parse_qs(urlparse(loc).query)["code"][0]

    # 3g. Exchange code + code_verifier at /oauth/token
    r_tok = s.post(
        f"{BASE_URL}/oauth/token",
        data={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": auth_code,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
        },
        timeout=5,
    )
    assert r_tok.status_code == 200
    tok_json = r_tok.json()
    access_token = tok_json["access_token"]

    # 3h. Use PKCE-minted access token on /mcp/citizen
    r_mcp = requests.post(
        f"{BASE_URL}/mcp/citizen",
        json={"jsonrpc": "2.0", "id": 99, "method": "tools/call", "params": {"name": "get_application_status", "arguments": {}}},
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=5,
    )
    assert r_mcp.status_code == 200
    mcp_res = json.loads(r_mcp.json()["result"]["content"][0]["text"])
    assert mcp_res["mobile"] == pkce_mobile
    print("✓ Full OAuth 2.1 DCR + PKCE S256 authorization flow & MCP invocation verified.")


def test_deemed_approval_idempotency():
    print("\n=== 4. Testing 15-Day Statutory Deemed Approval & Idempotency ===")
    m_sla = "9999000203"
    _cleanup_test_mobile(m_sla)

    conn = portal.get_db()
    cur = conn.cursor()
    sub_time = portal.now_ist() - timedelta(days=16)
    cur.execute(
        """INSERT INTO applications
           (application_no, applicant_name, mobile, dob, gender, marital_status,
            village, block, bank_account, ifsc, doc_path, status, submitted_at)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'PENDING', %s)
           RETURNING id, application_no""",
        ("SSP26990203", "SLA Test Citizen", m_sla, date(1952, 1, 1),
         "Male", "Married", "Sonari Gaon", "Sonari", "99918273645", "SBIN0003077",
         "/var/sewasetu/uploads/sla.pdf", sub_time),
    )
    sla_id, sla_no = cur.fetchone()
    conn.commit()
    cur.close(); conn.close()

    scripts_path = os.path.join(APP_DIR, "scripts", "deemed_approval.py")
    spec = importlib.util.spec_from_file_location("deemed_approval_test", scripts_path)
    deemed_job = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(deemed_job)

    # First run transitions the overdue PENDING application
    first_run = deemed_job.main()
    assert first_run >= 1

    # Second immediate run within the same minute must NOT transition or create duplicate audit logs
    second_run = deemed_job.main()
    assert second_run == 0

    conn = portal.get_db()
    cur = conn.cursor()
    cur.execute("SELECT count(*) FROM audit_log WHERE application_id = %s AND action = 'DEEMED_APPROVED'", (sla_id,))
    audit_count = cur.fetchone()[0]
    cur.close(); conn.close()

    assert audit_count == 1, f"Expected exactly 1 DEEMED_APPROVED audit entry, got {audit_count}"
    _cleanup_test_mobile(m_sla)
    print("✓ 15-day deemed approval transitions overdue PENDING cases and writes exactly 1 audit log entry.")


def test_eval_dashboard_and_original_portal():
    print("\n=== 5. Testing Evaluation Dashboard & Original Web Portal ===")
    r_run = requests.post(f"{BASE_URL}/eval-dashboard/run", allow_redirects=True, timeout=15)
    assert r_run.status_code == 200
    assert "10 of 10 passed (100.0%)" in r_run.text
    assert "✗ FAIL" not in r_run.text
    print("✓ POST /eval-dashboard/run executed all 10 scenarios with 10/10 PASS (100.0%).")

    # Original portal routes check (and verify public SMS gateway inbox is blocked with 403)
    assert requests.get(f"{BASE_URL}/", timeout=5).status_code == 200
    assert requests.get(f"{BASE_URL}/apply", timeout=5).status_code == 200
    assert requests.get(f"{BASE_URL}/status", timeout=5).status_code == 200
    assert requests.get(f"{BASE_URL}/admin", timeout=5).status_code == 200
    assert requests.get(f"{BASE_URL}/__gateway/", timeout=5).status_code == 403
    assert requests.get(f"{BASE_URL}/__gateway/api/messages", timeout=5).status_code == 403
    print("✓ Original web portal routes (/, /apply, /status, /admin) verified and public /__gateway/ blocked (403).")


def _parse_apply_page(html_text):
    import re as _re
    m_q = _re.search(r"What is (\d+)\s*\+\s*(\d+)\?", html_text)
    assert m_q, f"Could not find security question in HTML: {html_text[:300]}"
    ans = int(m_q.group(1)) + int(m_q.group(2))
    m_cid = _re.search(r'name="captcha_id"\s+value="([^"]*)"', html_text)
    cid = m_cid.group(1) if m_cid else ""
    return ans, cid


def test_apply_security_check_and_six_step_flow():
    print("\n=== 6. Testing /apply Security-Check Validation & 6-Step Citizen Flow ===")
    m_web = "9999000204"
    _cleanup_test_mobile(m_web)

    # 6a. HTTPS cross-site iframe cookie attributes check (both direct X-Forwarded-Proto=https
    # and internal Nginx proxy where X-Forwarded-Proto=http but X-Forwarded-Host is external)
    r_https = requests.get(f"{BASE_URL}/apply", headers={"X-Forwarded-Proto": "https"}, timeout=5)
    assert r_https.status_code == 200
    set_cookie_hdr = r_https.headers.get("Set-Cookie", "")
    assert "SameSite=None" in set_cookie_hdr and "Secure" in set_cookie_hdr and "Partitioned" in set_cookie_hdr

    r_nginx = requests.get(
        f"{BASE_URL}/apply",
        headers={
            "Host": "localhost:3000",
            "X-Forwarded-Host": "ais-dev-cpjh273foy7lavsbd4m2hb-578724348835.asia-southeast1.run.app",
            "X-Forwarded-Proto": "http",
        },
        timeout=5,
    )
    assert r_nginx.status_code == 200
    nginx_cookie_hdr = r_nginx.headers.get("Set-Cookie", "")
    assert "SameSite=None" in nginx_cookie_hdr and "Secure" in nginx_cookie_hdr and "Partitioned" in nginx_cookie_hdr
    print("✓ HTTPS and internal Nginx-proxied responses set SameSite=None; Secure; Partitioned on session cookie.")

    s = requests.Session()

    # 6b. Incorrect answer (wrong sum, non-numeric, empty) must be rejected & rotate question
    r1 = s.get(f"{BASE_URL}/apply", timeout=5)
    ans1, cid1 = _parse_apply_page(r1.text)

    r_wrong = s.post(
        f"{BASE_URL}/apply",
        data={"mobile": m_web, "captcha": str(ans1 + 1), "captcha_id": cid1},
        allow_redirects=False,
        timeout=5,
    )
    assert r_wrong.status_code == 200
    assert "Security check answer is incorrect. Please try again." in r_wrong.text
    assert f'value="{m_web}"' in r_wrong.text
    ans2, cid2 = _parse_apply_page(r_wrong.text)
    assert ans2 != ans1 and cid2 != cid1
    print("✓ Incorrect numeric answer rejected, mobile preserved, and new distinct question issued.")

    r_nonnum = s.post(
        f"{BASE_URL}/apply",
        data={"mobile": m_web, "captcha": "eleven", "captcha_id": cid2},
        allow_redirects=False,
        timeout=5,
    )
    assert r_nonnum.status_code == 200
    assert "Security check answer is incorrect. Please try again." in r_nonnum.text
    print("✓ Non-numeric security check answer rejected.")

    # 6c. Refreshed question: old answer/challenge invalidated, new answer accepted
    r_ref1 = s.get(f"{BASE_URL}/apply", timeout=5)
    ans_old, cid_old = _parse_apply_page(r_ref1.text)
    r_ref2 = s.get(f"{BASE_URL}/apply", timeout=5)
    ans_new, cid_new = _parse_apply_page(r_ref2.text)
    assert ans_new != ans_old and cid_new != cid_old

    # Submitting stale answer from before refresh must fail
    r_stale = s.post(
        f"{BASE_URL}/apply",
        data={"mobile": m_web, "captcha": str(ans_old), "captcha_id": cid_old},
        allow_redirects=False,
        timeout=5,
    )
    assert r_stale.status_code == 200
    assert "Security check answer is incorrect. Please try again." in r_stale.text
    print("✓ Refreshed question invalidated stale answer from previous page load.")

    # 6d. Correct answer succeeds and redirects to /verify
    r_fresh = s.get(f"{BASE_URL}/apply", timeout=5)
    ans_ok, cid_ok = _parse_apply_page(r_fresh.text)
    r_ok = s.post(
        f"{BASE_URL}/apply",
        data={"mobile": m_web, "captcha": str(ans_ok), "captcha_id": cid_ok},
        allow_redirects=False,
        timeout=5,
    )
    assert r_ok.status_code == 302 and "/verify" in r_ok.headers.get("Location", "")
    print(f"✓ Correct answer ({ans_ok}) accepted and redirected (302) to /verify.")

    # 6e. Repeated submission (replaying consumed answer/challenge without new GET /apply) must fail
    r_replay = s.post(
        f"{BASE_URL}/apply",
        data={"mobile": m_web, "captcha": str(ans_ok), "captcha_id": cid_ok},
        allow_redirects=False,
        timeout=5,
    )
    assert r_replay.status_code == 200
    assert "Security check answer is incorrect. Please try again." in r_replay.text
    print("✓ Repeated submission (replay of consumed security check) rejected.")

    # 6f. Multi-worker shared storage verification: challenge generated in one session/worker context is successfully validated in another worker context sharing the database
    s_worker1 = requests.Session()
    r_w1 = s_worker1.get(f"{BASE_URL}/apply", timeout=5)
    ans_w1, cid_w1 = _parse_apply_page(r_w1.text)
    s_worker2 = requests.Session()
    s_worker2.cookies.update(s_worker1.cookies)
    r_w2 = s_worker2.post(
        f"{BASE_URL}/apply",
        data={"mobile": m_web, "captcha": str(ans_w1), "captcha_id": cid_w1},
        allow_redirects=False,
        timeout=5,
    )
    assert r_w2.status_code == 302 and "/verify" in r_w2.headers.get("Location", "")
    print("✓ Shared database CAPTCHA storage successfully validated challenge across worker-equivalent session/request context.")


    # 6f. Verify incorrect OTP and expired OTP are rejected before accepting valid OTP
    conn = portal.get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, code FROM otps WHERE mobile = %s ORDER BY id DESC LIMIT 1", (m_web,))
    otp_id, otp_code = cur.fetchone()
    cur.close(); conn.close()

    wrong_otp = "000000" if otp_code != "000000" else "999999"
    r_bad_otp = s.post(f"{BASE_URL}/verify", data={"mobile": m_web, "otp": wrong_otp}, allow_redirects=False, timeout=5)
    assert r_bad_otp.status_code == 200 and "Invalid OTP." in r_bad_otp.text
    r_unauth_f1 = s.get(f"{BASE_URL}/form/1", allow_redirects=False, timeout=5)
    assert r_unauth_f1.status_code == 302 and "/apply" in r_unauth_f1.headers.get("Location", "")
    print("✓ Incorrect OTP rejected ('Invalid OTP.') and unverified access to /form/1 redirects to /apply.")

    # Backdate OTP to test expiry rejection
    conn = portal.get_db()
    cur = conn.cursor()
    cur.execute("UPDATE otps SET created_at = %s WHERE id = %s", (datetime.now() - timedelta(minutes=10), otp_id))
    conn.commit()
    cur.close(); conn.close()

    r_exp_otp = s.post(f"{BASE_URL}/verify", data={"mobile": m_web, "otp": otp_code}, allow_redirects=False, timeout=5)
    assert r_exp_otp.status_code == 302 and "/apply" in r_exp_otp.headers.get("Location", "")
    print("✓ Expired OTP rejected and redirected to /apply.")

    # Restore fresh timestamp for valid OTP verification
    conn = portal.get_db()
    cur = conn.cursor()
    cur.execute("UPDATE otps SET created_at = %s WHERE id = %s", (datetime.now(), otp_id))
    conn.commit()
    cur.close(); conn.close()

    r_ver = s.post(f"{BASE_URL}/verify", data={"mobile": m_web, "otp": otp_code}, allow_redirects=False, timeout=5)
    assert r_ver.status_code == 302 and "/form/1" in r_ver.headers.get("Location", "")
    r_get_f1 = s.get(f"{BASE_URL}/form/1", allow_redirects=False, timeout=5)
    assert r_get_f1.status_code == 200 and "Personal Details" in r_get_f1.text
    print("✓ Valid OTP accepted on POST /verify, redirected to /form/1, and session persisted on GET /form/1.")

    r_f1 = s.post(
        f"{BASE_URL}/form/1",
        data={"applicant_name": "Nalini Baruah", "dob": "15/06/1956", "gender": "Female", "marital_status": "Widowed", "husband_name": "Late Hiteswar Baruah"},
        allow_redirects=False,
        timeout=5,
    )
    assert r_f1.status_code == 302 and "/form/2" in r_f1.headers.get("Location", "")

    # 6h. Verify dependent Block -> Village/Town dropdown, empty state, and server-side validation on /form/2
    r_get_f2_empty = s.get(f"{BASE_URL}/form/2", timeout=5)
    assert r_get_f2_empty.status_code == 200
    assert "--Select a Block first--" in r_get_f2_empty.text
    for blk in ("Sonari", "Rajapara", "Dhemaji Pathar", "Borgaon", "Namti", "Khelua"):
        assert f'<option value="{blk}"' in r_get_f2_empty.text

    # Verify all seeded database applications match BLOCK_VILLAGES
    conn = portal.get_db()
    cur = conn.cursor()
    cur.execute("SELECT block, village FROM applications WHERE id <= 6")
    for s_blk, s_vil in cur.fetchall():
        assert s_blk in portal.BLOCK_VILLAGES
        assert s_vil in portal.BLOCK_VILLAGES[s_blk], f"Seeded ({s_blk}, {s_vil}) missing from BLOCK_VILLAGES"
    cur.close(); conn.close()

    # Dependent village list when block is selected
    r_get_f2_sonari = s.get(f"{BASE_URL}/form/2?block=Sonari", timeout=5)
    assert r_get_f2_sonari.status_code == 200
    for v_sonari in ("Disangmukh", "Sonari Gaon", "Sonari Town"):
        assert f'<option value="{v_sonari}"' in r_get_f2_sonari.text
    assert 'value="__OTHER__"' in r_get_f2_sonari.text

    import html as _html
    # Reject cross-block village mismatch server-side (Silapathar belongs to Dhemaji Pathar, not Sonari)
    r_f2_mismatch = s.post(
        f"{BASE_URL}/form/2",
        data={"block": "Sonari", "village": "Silapathar", "location_dropdown_mode": "1"},
        allow_redirects=False,
        timeout=5,
    )
    assert r_f2_mismatch.status_code == 200
    assert "belongs to block 'Dhemaji Pathar', not 'Sonari'" in _html.unescape(r_f2_mismatch.text)

    # Reject unmapped dropdown value when not using __OTHER__ manual mode
    r_f2_tamper = s.post(
        f"{BASE_URL}/form/2",
        data={"block": "Sonari", "village": "TamperedUnmappedVillage", "location_dropdown_mode": "1"},
        allow_redirects=False,
        timeout=5,
    )
    assert r_f2_tamper.status_code == 200
    assert "is not in the mapped list for block 'Sonari'" in _html.unescape(r_f2_tamper.text)

    # Reject empty manual-entry fallback
    r_f2_empty_other = s.post(
        f"{BASE_URL}/form/2",
        data={"block": "Sonari", "village": "__OTHER__", "village_other": "   ", "location_dropdown_mode": "1"},
        allow_redirects=False,
        timeout=5,
    )
    assert r_f2_empty_other.status_code == 200
    assert "village is required" in r_f2_empty_other.text

    # Accept valid manual-entry fallback for an unlisted village
    r_f2_manual_ok = s.post(
        f"{BASE_URL}/form/2",
        data={"block": "Sonari", "village": "__OTHER__", "village_other": "Sapekhati Tiniali", "location_dropdown_mode": "1"},
        allow_redirects=False,
        timeout=5,
    )
    assert r_f2_manual_ok.status_code == 302 and "/form/3" in r_f2_manual_ok.headers.get("Location", "")

    # Accept valid mapped village from dropdown
    r_f2 = s.post(
        f"{BASE_URL}/form/2",
        data={"village": "Sonari Town", "block": "Sonari", "location_dropdown_mode": "1"},
        allow_redirects=False,
        timeout=5,
    )
    assert r_f2.status_code == 302 and "/form/3" in r_f2.headers.get("Location", "")
    print("✓ Dependent Block -> Village/Town dropdown, empty state, cross-block mismatch rejection, and manual fallback verified.")

    r_f3 = s.post(
        f"{BASE_URL}/form/3",
        data={"bank_account": "31234567890", "ifsc": "SBIN0003077"},
        allow_redirects=False,
        timeout=5,
    )
    assert r_f3.status_code == 302 and "/upload" in r_f3.headers.get("Location", "")

    r_up = s.post(
        f"{BASE_URL}/upload",
        files={"document": ("voter_id.pdf", b"%PDF-1.4 Valid Voter ID", "application/pdf")},
        allow_redirects=False,
        timeout=5,
    )
    assert r_up.status_code == 302 and "/declaration" in r_up.headers.get("Location", "")

    r_decl = s.post(f"{BASE_URL}/declaration", data={"agree": "1"}, allow_redirects=True, timeout=5)
    assert r_decl.status_code == 200 and "SSP26" in r_decl.text
    _cleanup_test_mobile(m_web)
    print("✓ Complete 6-step citizen web application flow (/apply -> /verify -> /form/1..3 -> /upload -> /declaration) verified.")


def test_ack_pdf_and_otp_status_portal():
    print("=== 7. Testing Acknowledgment PDF Download & OTP-Only Citizen Status Portal ===")
    s_unauth = requests.Session()
    # 7a. Unauthenticated download of acknowledgment PDF must return 403 Forbidden
    r_unauth_pdf = s_unauth.get(f"{BASE_URL}/ack/1.pdf", timeout=5)
    assert r_unauth_pdf.status_code == 403
    print("✓ Unauthenticated access to /ack/<app_id>.pdf strictly blocked with 403 Forbidden.")

    # 7b. OTP-Only Citizen Status Login: Unregistered mobile rejected
    s_cit = requests.Session()
    unreg_mobile = "9999000999"
    r_unreg = s_cit.post(
        f"{BASE_URL}/status",
        data={"mobile": unreg_mobile},
        timeout=5,
    )
    assert r_unreg.status_code == 200
    assert "Mobile number not registered. Please apply first." in r_unreg.text
    print("✓ Status login with unregistered mobile rejected with 'Mobile number not registered. Please apply first.'")

    # 7c. Registered citizen mobile generates OTP and redirects to /status/verify
    reg_mobile = "9864011201"  # Application ID 1
    r_reg = s_cit.post(
        f"{BASE_URL}/status",
        data={"mobile": reg_mobile},
        allow_redirects=False,
        timeout=5,
    )
    assert r_reg.status_code == 302 and "/status/verify" in r_reg.headers.get("Location", "")
    print("✓ Status login for registered mobile (9864011201) accepted and redirected to /status/verify.")

    # 7d. Fetch simulated OTP from otps table
    conn = portal.get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, code FROM otps WHERE mobile = %s ORDER BY id DESC LIMIT 1", (reg_mobile,))
    status_otp_id, status_otp_code = cur.fetchone()
    cur.close(); conn.close()

    # 7e. GET /status/verify renders page with simulated OTP
    r_ver_page = s_cit.get(f"{BASE_URL}/status/verify", timeout=5)
    assert r_ver_page.status_code == 200
    assert "Verify OTP for Status Tracking" in r_ver_page.text
    assert status_otp_code in r_ver_page.text

    # 7f. Incorrect OTP is rejected
    wrong_otp = "000000" if status_otp_code != "000000" else "999999"
    r_bad_ver = s_cit.post(
        f"{BASE_URL}/status/verify",
        data={"mobile": reg_mobile, "otp": wrong_otp},
        timeout=5,
    )
    assert r_bad_ver.status_code == 200
    assert "Invalid OTP." in r_bad_ver.text
    print("✓ Status OTP verification strictly rejects incorrect OTP.")

    # 7g. Expired OTP is rejected
    conn = portal.get_db()
    cur = conn.cursor()
    cur.execute("UPDATE otps SET created_at = %s WHERE id = %s",
                (datetime.now() - timedelta(minutes=10), status_otp_id))
    conn.commit()
    cur.close(); conn.close()

    r_exp_ver = s_cit.post(
        f"{BASE_URL}/status/verify",
        data={"mobile": reg_mobile, "otp": status_otp_code},
        allow_redirects=False,
        timeout=5,
    )
    assert r_exp_ver.status_code == 302 and "/status" in r_exp_ver.headers.get("Location", "")
    print("✓ Expired status OTP rejected and redirected to /status.")

    # Restore valid OTP timestamp
    conn = portal.get_db()
    cur = conn.cursor()
    cur.execute("UPDATE otps SET created_at = %s WHERE id = %s",
                (datetime.now(), status_otp_id))
    conn.commit()
    cur.close(); conn.close()

    # 7h. Correct OTP succeeds and redirects to applicant's application view
    r_ok_ver = s_cit.post(
        f"{BASE_URL}/status/verify",
        data={"mobile": reg_mobile, "otp": status_otp_code},
        allow_redirects=False,
        timeout=5,
    )
    assert r_ok_ver.status_code == 302 and "/application/1" in r_ok_ver.headers.get("Location", "")
    print("✓ Valid status OTP accepted and redirected to /application/1.")

    # 7i. View application details and download acknowledgment PDF
    r_app_view = s_cit.get(f"{BASE_URL}/application/1", timeout=5)
    assert r_app_view.status_code == 200
    assert "SSP26100101" in r_app_view.text
    assert 'href="/ack/1.pdf"' in r_app_view.text
    assert 'download' in r_app_view.text

    # Cross-citizen authorization check: citizen 9864011201 cannot view application 2 (owned by 9864011202)
    r_other_app = s_cit.get(f"{BASE_URL}/application/2", timeout=5)
    assert r_other_app.status_code == 404
    print("✓ Cross-citizen application access blocked (404 Not Found).")

    # Cross-citizen PDF download check: citizen 9864011201 cannot download application 2 PDF
    r_other_pdf = s_cit.get(f"{BASE_URL}/ack/2.pdf", timeout=5)
    assert r_other_pdf.status_code == 403
    print("✓ Cross-citizen acknowledgment PDF download blocked with 403 Forbidden.")

    # 7j. Owning citizen downloads acknowledgment PDF with proper attachment header
    r_ack_pdf = s_cit.get(f"{BASE_URL}/ack/1.pdf", timeout=5)
    assert r_ack_pdf.status_code == 200
    assert r_ack_pdf.headers.get("Content-Type") == "application/pdf"
    disp = r_ack_pdf.headers.get("Content-Disposition", "")
    assert "attachment" in disp and "SewaSetu_Ack_1.pdf" in disp
    assert r_ack_pdf.content.startswith(b"%PDF-")
    print(f"✓ Valid Acknowledgment PDF downloaded with Content-Disposition: '{disp}'.")

    # 7k. Retired /status/reset redirects gracefully
    r_reset = s_cit.get(f"{BASE_URL}/status/reset", allow_redirects=False, timeout=5)
    assert r_reset.status_code == 302 and "/status" in r_reset.headers.get("Location", "")
    print("✓ Retired /status/reset redirects gracefully to OTP-only /status.")

    # 7l. Admin authentication continues to work with password
    s_adm = requests.Session()
    r_adm_bad = s_adm.post(
        f"{BASE_URL}/admin",
        data={"username": "admin", "password": "wrong-password"},
        timeout=5,
    )
    assert "Invalid credentials." in r_adm_bad.text
    r_adm_ok = s_adm.post(
        f"{BASE_URL}/admin",
        data={"username": portal.ADMIN_USERNAME, "password": portal.ADMIN_PASSWORD},
        allow_redirects=False,
        timeout=5,
    )
    assert r_adm_ok.status_code == 302 and "/admin/dashboard" in r_adm_ok.headers.get("Location", "")
    r_dash = s_adm.get(f"{BASE_URL}/admin/dashboard", timeout=5)
    assert r_dash.status_code == 200 and "Dashboard" in r_dash.text
    # Admin can download any acknowledgment PDF
    r_adm_pdf = s_adm.get(f"{BASE_URL}/ack/2.pdf", timeout=5)
    assert r_adm_pdf.status_code == 200 and "attachment" in r_adm_pdf.headers.get("Content-Disposition", "")
    print("✓ Officer /admin password authentication and dashboard/PDF download verified.")


def test_render_deployment_readiness():
    print("\n=== 8. Testing Render Deployment Readiness (PostgreSQL Strictness, Secrets, OTP Isolation) ===")
    import db_compat

    # 8a. URL normalization for Render postgres:// connection strings
    assert db_compat.normalize_database_url("postgres://u:p@host:5432/sewasetu") == "postgresql://u:p@host:5432/sewasetu"
    assert db_compat.normalize_database_url("postgresql://u:p@host:5432/sewasetu") == "postgresql://u:p@host:5432/sewasetu"
    print("✓ Render postgres:// to postgresql:// URL normalization verified.")

    # 8b. Strict failure in production when DATABASE_URL is missing or PostgreSQL is unreachable (no SQLite fallback)
    orig_env = {k: os.environ.get(k) for k in ("RENDER", "APP_ENV", "REQUIRE_POSTGRES", "DATABASE_URL", "SECRET_KEY", "ADMIN_PASSWORD")}
    try:
        os.environ["RENDER"] = "true"
        os.environ.pop("DATABASE_URL", None)
        failed_missing_db = False
        try:
            db_compat.connect_db(portal.config)
        except RuntimeError as exc:
            failed_missing_db = "DATABASE_URL is required in production mode" in str(exc)
        assert failed_missing_db, "Expected RuntimeError when DATABASE_URL is missing in production"

        os.environ["DATABASE_URL"] = "postgres://sewasetu:bad@127.0.0.1:59999/sewasetu?connect_timeout=1"
        failed_unreachable_db = False
        try:
            db_compat.connect_db(portal.config)
        except RuntimeError as exc:
            failed_unreachable_db = "PostgreSQL database connection failed" in str(exc)
        assert failed_unreachable_db, "Expected RuntimeError when production PostgreSQL is unreachable"
        print("✓ Production mode strictly requires PostgreSQL and fails clearly without SQLite fallback.")

        # 8c. Production secret validation rejects default/placeholder secrets
        os.environ["SECRET_KEY"] = "ssp-prod-key-2023-donotshare"
        os.environ["ADMIN_PASSWORD"] = "change-me-before-deploying"
        failed_weak_secrets = False
        try:
            portal.validate_production_config()
        except RuntimeError as exc:
            failed_weak_secrets = "SECRET_KEY" in str(exc) and "ADMIN_PASSWORD" in str(exc)
        assert failed_weak_secrets, "Expected RuntimeError for placeholder production secrets"

        os.environ["SECRET_KEY"] = "strong-production-secret-key-998877"
        os.environ["ADMIN_PASSWORD"] = "StrongAdminPass!2026"
        portal.validate_production_config()
        print("✓ Production secret validation rejects default placeholders and accepts strong env secrets.")
    finally:
        for k, v in orig_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    # 8d. Verify schema.sql is strictly non-destructive (CREATE TABLE/INDEX IF NOT EXISTS only)
    schema_path = os.path.join(APP_DIR, "schema.sql")
    with open(schema_path, "r", encoding="utf-8") as fh:
        schema_sql = fh.read().upper()
    assert "CREATE TABLE IF NOT EXISTS" in schema_sql
    for forbidden in ("DROP TABLE", "DROP DATABASE", "TRUNCATE", "DELETE FROM"):
        assert forbidden not in schema_sql, f"Found destructive statement {forbidden} in schema.sql"
    print("✓ app/schema.sql verified non-destructive (CREATE TABLE/INDEX IF NOT EXISTS only).")

    # 8e. Verify unauthenticated ?mobile= query requests do not leak OTPs on /verify or /status/verify
    s_attacker = requests.Session()
    r_steal_status = s_attacker.get(f"{BASE_URL}/status/verify?mobile=9864011201", allow_redirects=False, timeout=5)
    assert r_steal_status.status_code == 302 and "/status" in r_steal_status.headers.get("Location", "")
    r_steal_apply = s_attacker.get(f"{BASE_URL}/verify?mobile=9864011201", allow_redirects=False, timeout=5)
    assert r_steal_apply.status_code == 302 and "/apply" in r_steal_apply.headers.get("Location", "")
    print("✓ Unauthenticated ?mobile= OTP scraping blocked on both /verify and /status/verify.")


def main():
    app_id, app_no, test_mobile, token_citizen = test_mcp_citizen_endpoint_and_validation()
    try:
        test_jwt_security_and_officer_mcp(app_id, app_no, token_citizen)
        test_oauth_pkce_external_client_flow()
        test_deemed_approval_idempotency()
        test_eval_dashboard_and_original_portal()
        test_apply_security_check_and_six_step_flow()
        test_ack_pdf_and_otp_status_portal()
        test_render_deployment_readiness()
    finally:
        _cleanup_test_mobile(test_mobile)
        _cleanup_test_mobile("9999000202")
        _cleanup_test_mobile("9999000204")

    print("\n=======================================================")
    print("ALL AUDIT, SECURITY, MCP, OAUTH & EVAL TESTS PASSED!")
    print("=======================================================")


if __name__ == "__main__":
    main()

