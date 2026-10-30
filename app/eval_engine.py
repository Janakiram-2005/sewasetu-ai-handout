# -*- coding: utf-8 -*-
"""
Evaluation Engine for Sewa Setu AI Agent Integration.

Simulates fictional citizen personas and block officer scenarios against the
Streamable HTTP MCP JSON-RPC dispatcher (`handle_mcp_rpc`) using real RS256
JWT tokens and evaluates outcomes against the live database.
Produces structured conversation transcripts, tool traces, database assertion
checks, and pass/fail metrics for `/eval-dashboard`.
"""

import base64
import importlib.util
import json
import os
from datetime import date, datetime, timedelta

import app as portal
import oauth
from mcp_server import handle_mcp_rpc


def _mint_test_token(subject, role, scope="citizen", ttl=3600):
    """Mint a real RS256 token using the portal's active signing keys."""
    audience = oauth.ISSUER
    token, _ = oauth.mint_access_token(
        subject=subject,
        role=role,
        scope=scope,
        audience=audience,
        client_id="eval-dashboard-client",
        ttl=ttl,
        kind="access",
    )
    return token


def _cleanup_eval_records(mobiles):
    """Ensure repeatable, isolated evaluation runs without touching seed or user data."""
    conn = portal.get_db()
    cur = conn.cursor()
    for m in mobiles:
        cur.execute("SELECT id, doc_path FROM applications WHERE mobile = %s", (m,))
        rows = cur.fetchall()
        for app_id, doc_path in rows:
            cur.execute("DELETE FROM audit_log WHERE application_id = %s", (app_id,))
            if doc_path and os.path.exists(doc_path) and os.path.basename(doc_path).startswith("99990001"):
                try:
                    os.remove(doc_path)
                except OSError:
                    pass
        cur.execute("DELETE FROM applications WHERE mobile = %s", (m,))
        cur.execute("DELETE FROM portal_users WHERE mobile = %s", (m,))
        cur.execute("DELETE FROM otps WHERE mobile = %s", (m,))
        cur.execute("DELETE FROM oauth_refresh_tokens WHERE subject = %s", ("citizen:" + m,))
        cur.execute("DELETE FROM oauth_codes WHERE subject = %s", ("citizen:" + m,))
    conn.commit()
    cur.close()
    conn.close()


def _parse_mcp_tool_output(rpc_response):
    """Extract parsed JSON or error string from a JSON-RPC 2.0 MCP response."""
    if not isinstance(rpc_response, dict):
        return False, {}, "Invalid RPC response"
    if "error" in rpc_response:
        return True, rpc_response["error"], rpc_response["error"].get("message", "")
    result = rpc_response.get("result") or {}
    is_error = bool(result.get("isError"))
    content = result.get("content") or []
    text = content[0].get("text", "") if content else ""
    if is_error:
        return True, {"error": text}, text
    try:
        return False, json.loads(text), text
    except Exception:
        return False, {"raw": text}, text


def run_all_evaluations():
    """
    Executes all 10 evaluation scenarios across citizen personas, security
    boundaries, officer decisions, and statutory SLA automation using isolated
    test records and real JSON-RPC 2.0 MCP invocations.
    """
    eval_timestamp = portal.now_ist().strftime("%Y-%m-%d %H:%M:%S IST")
    results = []

    # Dedicated isolated mobile range (9999000101 - 9999000108) cleaned before each run
    m_kamala = "9999000101"
    m_bhaben = "9999000102"
    m_tarali = "9999000103"
    m_bipul  = "9999000104"
    m_other  = "9999000105"
    m_reject = "9999000106"
    m_sla_overdue = "9999000107"
    m_sla_recent  = "9999000108"

    eval_mobiles = [
        m_kamala, m_bhaben, m_tarali, m_bipul,
        m_other, m_reject, m_sla_overdue, m_sla_recent,
    ]
    _cleanup_eval_records(eval_mobiles)

    token_kamala = _mint_test_token(f"citizen:{m_kamala}", "citizen", "citizen")
    token_bhaben = _mint_test_token(f"citizen:{m_bhaben}", "citizen", "citizen")
    token_tarali = _mint_test_token(f"citizen:{m_tarali}", "citizen", "citizen")
    token_bipul  = _mint_test_token(f"citizen:{m_bipul}",  "citizen", "citizen")
    token_other  = _mint_test_token(f"citizen:{m_other}",  "citizen", "citizen")
    token_reject = _mint_test_token(f"citizen:{m_reject}", "citizen", "citizen")
    token_officer = _mint_test_token("officer:admin", "officer", "officer")

    sample_pdf_b64 = base64.b64encode(b"%PDF-1.4 Verified Electoral Roll Age Proof").decode("ascii")

    kamala_app_no = None
    kamala_app_id = None

    # -------------------------------------------------------------------------
    # Scenario 1: Eligible Senior Citizen Application (Kamala Devi)
    # -------------------------------------------------------------------------
    s1_persona = {
        "name": "Kamala Devi",
        "age": 68,
        "village": "Disangmukh",
        "block": "Sonari",
        "story": "Kamala Devi is a 68-year-old widow living in Disangmukh village. She has her voter ID and SBI bank passbook and submits her Old Age Pension application through the Citizen MCP server.",
        "voice": "Namaskar, I am 68 years old and live alone in Disangmukh. My husband late Bhupen passed away four years ago. Can you submit my old age pension application?",
    }
    s1_args = {
        "applicant_name": "Kamala Devi",
        "dob": "14/03/1958",
        "gender": "Female",
        "marital_status": "Widowed",
        "husband_name": "Late Bhupen Bora",
        "village": "Disangmukh",
        "block": "Sonari",
        "bank_account": "30918273645",
        "ifsc": "SBIN0003077",
        "document_name": "voter_id_kamala.pdf",
        "document_base64": sample_pdf_b64,
    }
    s1_rpc = {
        "jsonrpc": "2.0",
        "id": "eval-1",
        "method": "tools/call",
        "params": {"name": "submit_application", "arguments": s1_args},
    }
    s1_resp = handle_mcp_rpc(s1_rpc, "citizen", auth_token=token_kamala)
    s1_is_err, s1_data, _ = _parse_mcp_tool_output(s1_resp)

    conn = portal.get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, application_no, applicant_name, status, block, village FROM applications WHERE mobile = %s",
        (m_kamala,)
    )
    db_row = cur.fetchone()
    cur.close(); conn.close()

    s1_passed = (
        not s1_is_err
        and s1_data.get("success") is True
        and db_row is not None
        and db_row[3] == "PENDING"
        and db_row[4] == "Sonari"
    )
    if db_row:
        kamala_app_id = db_row[0]
        kamala_app_no = db_row[1]

    results.append({
        "id": "scenario-1",
        "title": "Eligible Senior Citizen Application",
        "category": "Eligibility & Submission",
        "persona": s1_persona,
        "mcp_request": s1_rpc,
        "mcp_response": s1_resp,
        "db_assertion": {
            "sql": f"SELECT id, application_no, status, block FROM applications WHERE mobile = '{m_kamala}'",
            "expected": "Record exists with status='PENDING' and block='Sonari'",
            "actual": f"id={db_row[0] if db_row else 'None'}, app_no={db_row[1] if db_row else 'None'}, status={db_row[3] if db_row else 'None'}",
            "passed": s1_passed,
        },
        "passed": s1_passed,
        "explanation": "Valid senior citizen aged 68 residing in eligible block Sonari was accepted via Citizen MCP and registered as PENDING with an official application number.",
    })

    # -------------------------------------------------------------------------
    # Scenario 2: Underage Applicant (Bhaben Bora, Age 58)
    # -------------------------------------------------------------------------
    s2_persona = {
        "name": "Bhaben Bora",
        "age": 58,
        "village": "Borgaon Bazar",
        "block": "Borgaon",
        "story": "Bhaben Bora is 58 years old and attempts to apply 2 years early before turning 60. The statutory rule strictly mandates a minimum age of 60.",
        "voice": "I am 58 years old, please file my pension application so I get benefits as soon as possible.",
    }
    curr_year = portal.now_ist().year
    dob_underage = f"10/05/{curr_year - 58}"
    s2_args = {
        "applicant_name": "Bhaben Bora",
        "dob": dob_underage,
        "gender": "Male",
        "marital_status": "Married",
        "village": "Borgaon Bazar",
        "block": "Borgaon",
        "bank_account": "44918273645",
        "ifsc": "SBIN0003077",
        "document_name": "birth_cert.pdf",
        "document_base64": sample_pdf_b64,
    }
    s2_rpc = {
        "jsonrpc": "2.0",
        "id": "eval-2",
        "method": "tools/call",
        "params": {"name": "submit_application", "arguments": s2_args},
    }
    s2_resp = handle_mcp_rpc(s2_rpc, "citizen", auth_token=token_bhaben)
    s2_is_err, _, s2_text = _parse_mcp_tool_output(s2_resp)

    conn = portal.get_db()
    cur = conn.cursor()
    cur.execute("SELECT count(*) FROM applications WHERE mobile = %s", (m_bhaben,))
    s2_count = cur.fetchone()[0]
    cur.close(); conn.close()

    s2_passed = s2_is_err and ("applicant must be 60 years of age or above" in s2_text) and (s2_count == 0)

    results.append({
        "id": "scenario-2",
        "title": "Underage Applicant Rejection (Statutory Age Boundary)",
        "category": "Age Boundary Check",
        "persona": s2_persona,
        "mcp_request": s2_rpc,
        "mcp_response": s2_resp,
        "db_assertion": {
            "sql": f"SELECT count(*) FROM applications WHERE mobile = '{m_bhaben}'",
            "expected": "0 records (no database row created on validation error)",
            "actual": f"{s2_count} records found",
            "passed": s2_count == 0,
        },
        "passed": s2_passed,
        "explanation": "Citizen MCP server rejected applicant aged 58 with 'applicant must be 60 years of age or above'. Zero records inserted into database.",
    })

    # -------------------------------------------------------------------------
    # Scenario 3: Unsupported Administrative Block (Tarali Chaliha)
    # -------------------------------------------------------------------------
    s3_persona = {
        "name": "Tarali Chaliha",
        "age": 64,
        "village": "Moranhat",
        "block": "Dibrugarh Rural",
        "story": "Tarali is 64 years old but resides in 'Dibrugarh Rural', which is outside the 6 designated Purvanchal scheme development blocks.",
        "voice": "I am 64 from Moranhat in Dibrugarh Rural block. Please submit my pension form.",
    }
    s3_args = {
        "applicant_name": "Tarali Chaliha",
        "dob": "20/08/1962",
        "gender": "Female",
        "marital_status": "Married",
        "village": "Moranhat",
        "block": "Dibrugarh Rural",
        "bank_account": "55918273645",
        "ifsc": "SBIN0003077",
        "document_name": "voter_id.pdf",
        "document_base64": sample_pdf_b64,
    }
    s3_rpc = {
        "jsonrpc": "2.0",
        "id": "eval-3",
        "method": "tools/call",
        "params": {"name": "submit_application", "arguments": s3_args},
    }
    s3_resp = handle_mcp_rpc(s3_rpc, "citizen", auth_token=token_tarali)
    s3_is_err, _, s3_text = _parse_mcp_tool_output(s3_resp)

    conn = portal.get_db()
    cur = conn.cursor()
    cur.execute("SELECT count(*) FROM applications WHERE mobile = %s", (m_tarali,))
    s3_count = cur.fetchone()[0]
    cur.close(); conn.close()

    s3_passed = s3_is_err and ("block must be one of" in s3_text) and (s3_count == 0)

    results.append({
        "id": "scenario-3",
        "title": "Unsupported Administrative Block Check",
        "category": "Jurisdictional Boundary",
        "persona": s3_persona,
        "mcp_request": s3_rpc,
        "mcp_response": s3_resp,
        "db_assertion": {
            "sql": f"SELECT count(*) FROM applications WHERE mobile = '{m_tarali}'",
            "expected": "0 records in database",
            "actual": f"{s3_count} records",
            "passed": s3_count == 0,
        },
        "passed": s3_passed,
        "explanation": "Citizen MCP server rejected block 'Dibrugarh Rural' because it is outside the statutory Purvanchal blocks: Sonari, Rajapara, Dhemaji Pathar, Borgaon, Namti, Khelua.",
    })

    # -------------------------------------------------------------------------
    # Scenario 4: Missing Age-Proof Document (Bipul Kalita)
    # -------------------------------------------------------------------------
    s4_persona = {
        "name": "Bipul Kalita",
        "age": 66,
        "village": "Khelua Gaon",
        "block": "Khelua",
        "story": "Bipul is 66 from Khelua. He provides personal and bank details via MCP but omits the mandatory age-proof document attachment.",
        "voice": "I don't have my age proof scanned right now, can you just submit with my bank details?",
    }
    s4_args = {
        "applicant_name": "Bipul Kalita",
        "dob": "12/01/1960",
        "gender": "Male",
        "marital_status": "Married",
        "village": "Khelua Gaon",
        "block": "Khelua",
        "bank_account": "66918273645",
        "ifsc": "SBIN0003077",
    }
    s4_rpc = {
        "jsonrpc": "2.0",
        "id": "eval-4",
        "method": "tools/call",
        "params": {"name": "submit_application", "arguments": s4_args},
    }
    s4_resp = handle_mcp_rpc(s4_rpc, "citizen", auth_token=token_bipul)
    s4_is_err, _, s4_text = _parse_mcp_tool_output(s4_resp)

    conn = portal.get_db()
    cur = conn.cursor()
    cur.execute("SELECT count(*) FROM applications WHERE mobile = %s", (m_bipul,))
    s4_count = cur.fetchone()[0]
    cur.close(); conn.close()

    s4_passed = s4_is_err and ("age proof document is required" in s4_text) and (s4_count == 0)

    results.append({
        "id": "scenario-4",
        "title": "Mandatory Age Proof Document Enforcement",
        "category": "Document Requirements",
        "persona": s4_persona,
        "mcp_request": s4_rpc,
        "mcp_response": s4_resp,
        "db_assertion": {
            "sql": f"SELECT count(*) FROM applications WHERE mobile = '{m_bipul}'",
            "expected": "0 records; MCP tool returns 'age proof document is required'",
            "actual": f"{s4_count} records; error='{s4_text}'",
            "passed": s4_passed,
        },
        "passed": s4_passed,
        "explanation": "Citizen MCP server strictly enforced the statutory requirement for an age-proof document and refused to fabricate a placeholder file.",
    })

    # -------------------------------------------------------------------------
    # Scenario 5: Duplicate Active Application Rejection
    # -------------------------------------------------------------------------
    s5_persona = {
        "name": "Kamala Devi (Duplicate Attempt)",
        "age": 68,
        "village": "Disangmukh",
        "block": "Sonari",
        "story": "Kamala Devi already has a PENDING application (created in Scenario 1). She attempts to submit a second application under the same mobile number.",
        "voice": "I forgot if I submitted, let me apply once more just in case.",
    }
    s5_rpc = {
        "jsonrpc": "2.0",
        "id": "eval-5",
        "method": "tools/call",
        "params": {"name": "submit_application", "arguments": s1_args},
    }
    s5_resp = handle_mcp_rpc(s5_rpc, "citizen", auth_token=token_kamala)
    s5_is_err, _, s5_text = _parse_mcp_tool_output(s5_resp)

    conn = portal.get_db()
    cur = conn.cursor()
    cur.execute("SELECT count(*) FROM applications WHERE mobile = %s", (m_kamala,))
    s5_count = cur.fetchone()[0]
    cur.close(); conn.close()

    s5_passed = s5_is_err and ("already exists" in s5_text) and (s5_count == 1)

    results.append({
        "id": "scenario-5",
        "title": "Duplicate Active Application Prevention",
        "category": "Data Integrity & Constraints",
        "persona": s5_persona,
        "mcp_request": s5_rpc,
        "mcp_response": s5_resp,
        "db_assertion": {
            "sql": f"SELECT count(*) FROM applications WHERE mobile = '{m_kamala}'",
            "expected": "Exactly 1 active application; second submission blocked",
            "actual": f"count={s5_count}",
            "passed": s5_count == 1,
        },
        "passed": s5_passed,
        "explanation": "Citizen MCP server blocked duplicate submission because an active PENDING application already exists for this mobile number.",
    })

    # -------------------------------------------------------------------------
    # Scenario 6: Cross-Citizen Access Security Boundary
    # -------------------------------------------------------------------------
    s6_persona = {
        "name": "Unauthorized Citizen (Ramen Gogoi)",
        "age": 62,
        "village": "Rajapara",
        "block": "Rajapara",
        "story": "Citizen B attempts to query the status and private bank/personal details of Citizen A (Kamala Devi) using Citizen B's OAuth bearer token.",
        "voice": f"Show me the status of application {kamala_app_no}.",
    }
    s6_rpc = {
        "jsonrpc": "2.0",
        "id": "eval-6",
        "method": "tools/call",
        "params": {"name": "get_application_status", "arguments": {"application_no": kamala_app_no or "SSP26100101"}},
    }
    s6_resp = handle_mcp_rpc(s6_rpc, "citizen", auth_token=token_other)
    s6_is_err, s6_data, _ = _parse_mcp_tool_output(s6_resp)
    s6_passed = (not s6_is_err) and (s6_data.get("found") is False)

    results.append({
        "id": "scenario-6",
        "title": "Cross-Citizen Access Security Boundary",
        "category": "Authorization & Privacy",
        "persona": s6_persona,
        "mcp_request": s6_rpc,
        "mcp_response": s6_resp,
        "db_assertion": {
            "sql": f"SELECT * FROM applications WHERE application_no = '{kamala_app_no}' AND mobile = '{m_other}'",
            "expected": "found=False (Citizen B cannot inspect Citizen A's application)",
            "actual": f"found={s6_data.get('found')}",
            "passed": s6_passed,
        },
        "passed": s6_passed,
        "explanation": "Strict tenant isolation enforced: Citizens can only query application records bound to their own OTP-verified mobile identity (`sub = citizen:<mobile>`).",
    })

    # -------------------------------------------------------------------------
    # Scenario 7: Role & Privilege Separation (Citizen calling Officer tools)
    # -------------------------------------------------------------------------
    s7_persona = {
        "name": "Malicious / Misconfigured Citizen Assistant",
        "age": 68,
        "village": "Disangmukh",
        "block": "Sonari",
        "story": "A client holding Kamala Devi's valid citizen JWT attempts to invoke `approve_application` on the Officer MCP server (`/mcp/officer`).",
        "voice": "Approve my application immediately with note 'Self-approved'.",
    }
    s7_rpc = {
        "jsonrpc": "2.0",
        "id": "eval-7",
        "method": "tools/call",
        "params": {"name": "approve_application", "arguments": {"application_id": kamala_app_id, "note": "Self-approved"}},
    }
    s7_resp = handle_mcp_rpc(s7_rpc, "officer", auth_token=token_kamala)
    s7_err_obj = s7_resp.get("error") or {}

    conn = portal.get_db()
    cur = conn.cursor()
    cur.execute("SELECT status FROM applications WHERE id = %s", (kamala_app_id,))
    s7_db_status = cur.fetchone()[0]
    cur.close(); conn.close()

    s7_passed = (s7_err_obj.get("code") == -32002) and (s7_db_status == "PENDING")

    results.append({
        "id": "scenario-7",
        "title": "Role & Privilege Separation Enforcement",
        "category": "Access Control (RBAC)",
        "persona": s7_persona,
        "mcp_request": s7_rpc,
        "mcp_response": s7_resp,
        "db_assertion": {
            "sql": f"SELECT status FROM applications WHERE id = {kamala_app_id}",
            "expected": "JSON-RPC error -32002 (requires role 'officer'); DB status remains 'PENDING'",
            "actual": f"error_code={s7_err_obj.get('code')}, db_status='{s7_db_status}'",
            "passed": s7_passed,
        },
        "passed": s7_passed,
        "explanation": "Citizen bearer tokens are rejected with JSON-RPC error -32002 on the Officer MCP server. Database state remained untouched.",
    })

    # -------------------------------------------------------------------------
    # Scenario 8: Officer Case Review & Approval (Kamala Devi)
    # -------------------------------------------------------------------------
    s8_persona = {
        "name": "Block Development Officer (Sonari)",
        "age": 45,
        "village": "BDO Office Sonari",
        "block": "Sonari",
        "story": "The authorized block officer inspects Kamala Devi's pending case via `/mcp/officer`, verifies her age proof against official records, and approves the pension application.",
        "voice": "Review application for Kamala Devi in Sonari block and approve upon verification.",
    }
    s8_args = {
        "application_id": kamala_app_id,
        "note": "Verified electoral roll and age proof. Eligible under scheme rules.",
    }
    s8_rpc = {
        "jsonrpc": "2.0",
        "id": "eval-8",
        "method": "tools/call",
        "params": {"name": "approve_application", "arguments": s8_args},
    }
    s8_resp = handle_mcp_rpc(s8_rpc, "officer", auth_token=token_officer)
    s8_is_err, s8_data, _ = _parse_mcp_tool_output(s8_resp)

    conn = portal.get_db()
    cur = conn.cursor()
    cur.execute("SELECT status, decided_by, decided_at FROM applications WHERE id = %s", (kamala_app_id,))
    s8_db = cur.fetchone()
    cur.execute("SELECT action, actor, note FROM audit_log WHERE application_id = %s AND action = 'APPROVED'", (kamala_app_id,))
    s8_audit = cur.fetchone()
    cur.close(); conn.close()

    s8_passed = (
        not s8_is_err
        and s8_data.get("status") == "APPROVED"
        and s8_db is not None
        and s8_db[0] == "APPROVED"
        and s8_audit is not None
    )

    results.append({
        "id": "scenario-8",
        "title": "Officer Case Review and Approval",
        "category": "Officer Decision & Audit",
        "persona": s8_persona,
        "mcp_request": s8_rpc,
        "mcp_response": s8_resp,
        "db_assertion": {
            "sql": f"SELECT status, decided_by FROM applications WHERE id = {kamala_app_id}",
            "expected": "status='APPROVED', decided_by='admin', audit entry created",
            "actual": f"status={s8_db[0] if s8_db else 'None'}, decided_by={s8_db[1] if s8_db else 'None'}, audit={s8_audit[0] if s8_audit else 'None'}",
            "passed": s8_passed,
        },
        "passed": s8_passed,
        "explanation": f"Officer approved application {kamala_app_no} via Officer MCP server. Database updated to APPROVED and immutable audit log entry recorded.",
    })

    # -------------------------------------------------------------------------
    # Scenario 9: Officer Inspection & Rejection with Stated Grounds
    # -------------------------------------------------------------------------
    # Submit a valid pending case via Citizen MCP for Digen Phukan, then reject via Officer MCP
    s9_sub_rpc = {
        "jsonrpc": "2.0",
        "id": "eval-9-prep",
        "method": "tools/call",
        "params": {
            "name": "submit_application",
            "arguments": {
                "applicant_name": "Digen Phukan",
                "dob": "10/04/1957",
                "gender": "Male",
                "marital_status": "Married",
                "village": "Boko",
                "block": "Rajapara",
                "bank_account": "77918273645",
                "ifsc": "SBIN0004120",
                "document_name": "unverified_cert.pdf",
                "document_base64": sample_pdf_b64,
            },
        },
    }
    s9_sub_resp = handle_mcp_rpc(s9_sub_rpc, "citizen", auth_token=token_reject)
    _, s9_sub_data, _ = _parse_mcp_tool_output(s9_sub_resp)
    rej_id = s9_sub_data.get("application_id")
    rej_app_no = s9_sub_data.get("application_no")

    s9_persona = {
        "name": "Block Development Officer (Rajapara)",
        "age": 42,
        "village": "BDO Office Rajapara",
        "block": "Rajapara",
        "story": "Officer investigates Digen Phukan's application and discovers the attached age proof document is illegible and unverified by the village headman.",
        "voice": "Reject application with reason: Document illegible and unverified by Gaonburah.",
    }
    s9_args = {
        "application_id": rej_id,
        "reason": "Document illegible and unverified by Gaonburah",
    }
    s9_rpc = {
        "jsonrpc": "2.0",
        "id": "eval-9",
        "method": "tools/call",
        "params": {"name": "reject_application", "arguments": s9_args},
    }
    s9_resp = handle_mcp_rpc(s9_rpc, "officer", auth_token=token_officer)
    s9_is_err, s9_data, _ = _parse_mcp_tool_output(s9_resp)

    conn = portal.get_db()
    cur = conn.cursor()
    cur.execute("SELECT status, decided_by FROM applications WHERE id = %s", (rej_id,))
    s9_db = cur.fetchone()
    cur.execute("SELECT action, actor, note FROM audit_log WHERE application_id = %s AND action = 'REJECTED'", (rej_id,))
    s9_audit = cur.fetchone()
    cur.close(); conn.close()

    s9_passed = (
        not s9_is_err
        and s9_data.get("status") == "REJECTED"
        and s9_db is not None
        and s9_db[0] == "REJECTED"
        and s9_audit is not None
    )

    results.append({
        "id": "scenario-9",
        "title": "Officer Case Rejection with Stated Grounds",
        "category": "Officer Decision & Audit",
        "persona": s9_persona,
        "mcp_request": s9_rpc,
        "mcp_response": s9_resp,
        "db_assertion": {
            "sql": f"SELECT status, decided_by FROM applications WHERE id = {rej_id}",
            "expected": "status='REJECTED' with recorded reason in audit log",
            "actual": f"status={s9_db[0] if s9_db else 'None'}, audit_note='{s9_audit[2] if s9_audit else 'None'}'",
            "passed": s9_passed,
        },
        "passed": s9_passed,
        "explanation": f"Officer rejected application {rej_app_no} via Officer MCP server with statutory grounds recorded in the audit trail.",
    })

    # -------------------------------------------------------------------------
    # Scenario 10: 15-Day Statutory Deemed Approval (RTPS Act)
    # -------------------------------------------------------------------------
    conn = portal.get_db()
    cur = conn.cursor()
    test_clock = portal.now_ist()
    overdue_submission = test_clock - timedelta(days=19)
    recent_submission = test_clock - timedelta(days=10)

    # 10a: Overdue PENDING application (19 days old -> should become DEEMED_APPROVED)
    cur.execute(
        """INSERT INTO applications
           (application_no, applicant_name, mobile, dob, gender, marital_status,
            village, block, bank_account, ifsc, doc_path, status, submitted_at)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'PENDING', %s)
           RETURNING id, application_no""",
        ("SSP26990107", "Moniram Saikia", m_sla_overdue, date(1953, 9, 15),
         "Male", "Married", "Silapathar", "Dhemaji Pathar", "88918273645", "PUNB0041200",
         "/var/sewasetu/uploads/moniram.pdf", overdue_submission)
    )
    sla_id, sla_app_no = cur.fetchone()
    portal.write_audit(cur, sla_id, "SUBMIT", f"applicant:{m_sla_overdue}")

    # 10b: Recent PENDING application (10 days old -> must remain PENDING)
    cur.execute(
        """INSERT INTO applications
           (application_no, applicant_name, mobile, dob, gender, marital_status,
            village, block, bank_account, ifsc, doc_path, status, submitted_at)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'PENDING', %s)
           RETURNING id, application_no""",
        ("SSP26990108", "Hema Phukan", m_sla_recent, date(1956, 6, 20),
         "Female", "Widowed", "Namti Chariali", "Namti", "88918273646", "PUNB0041200",
         "/var/sewasetu/uploads/hema.pdf", recent_submission)
    )
    recent_id, _ = cur.fetchone()
    portal.write_audit(cur, recent_id, "SUBMIT", f"applicant:{m_sla_recent}")

    # Also backdate Digen Phukan's REJECTED application to 20 days ago to verify
    # that deemed_approval NEVER overwrites an officer's prior decision.
    if rej_id is not None:
        cur.execute("UPDATE applications SET submitted_at = %s WHERE id = %s",
                    (test_clock - timedelta(days=20), rej_id))
    conn.commit()
    cur.close(); conn.close()

    s10_persona = {
        "name": "Moniram Saikia (SLA Breach Case)",
        "age": 73,
        "village": "Silapathar",
        "block": "Dhemaji Pathar",
        "story": "Moniram's application has been pending for 19 days without departmental action. Under the Purvanchal Right to Public Services Act (SLA = 15 days), it transitions to DEEMED_APPROVED while a 10-day pending case remains PENDING and a 20-day REJECTED case remains REJECTED.",
        "voice": "My application has been pending for more than 15 days without decision.",
    }

    scripts_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts", "deemed_approval.py")
    spec = importlib.util.spec_from_file_location("deemed_approval_eval", scripts_path)
    deemed_job = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(deemed_job)
    transitioned_nos = deemed_job.main(reference_time=test_clock)

    conn = portal.get_db()
    cur = conn.cursor()
    cur.execute("SELECT status, decided_by FROM applications WHERE id = %s", (sla_id,))
    s10_db = cur.fetchone()
    cur.execute("SELECT status FROM applications WHERE id = %s", (recent_id,))
    s10_recent_db = cur.fetchone()
    cur.execute("SELECT status FROM applications WHERE id = %s", (rej_id,))
    s10_rej_db = cur.fetchone()
    cur.execute("SELECT count(*) FROM audit_log WHERE application_id = %s AND action = 'DEEMED_APPROVED'", (sla_id,))
    s10_audit_count = cur.fetchone()[0]
    cur.close(); conn.close()

    s10_passed = (
        s10_db is not None
        and s10_db[0] == "DEEMED_APPROVED"
        and s10_db[1] == "RTPS-AUTO"
        and s10_audit_count == 1
        and s10_recent_db is not None
        and s10_recent_db[0] == "PENDING"
        and s10_rej_db is not None
        and s10_rej_db[0] == "REJECTED"
    )

    results.append({
        "id": "scenario-10",
        "title": "15-Day Statutory Deemed Approval Automation",
        "category": "Statutory SLA Enforcement",
        "persona": s10_persona,
        "mcp_request": {
            "cron_job": "scripts/deemed_approval.py",
            "reference_clock_ist": test_clock.isoformat(),
            "sla_days": portal.SLA_DAYS,
            "overdue_app_id": sla_id,
            "recent_app_id": recent_id,
            "decided_app_id": rej_id,
        },
        "mcp_response": {
            "transitioned_count": len(transitioned_nos) if isinstance(transitioned_nos, list) else int(transitioned_nos),
            "transitioned_applications": transitioned_nos,
            "overdue_case_status": s10_db[0] if s10_db else None,
            "recent_10d_case_status": s10_recent_db[0] if s10_recent_db else None,
            "officer_rejected_20d_status": s10_rej_db[0] if s10_rej_db else None,
        },
        "db_assertion": {
            "sql": f"SELECT status, decided_by FROM applications WHERE id IN ({sla_id}, {recent_id}, {rej_id})",
            "expected": "19d PENDING -> DEEMED_APPROVED (RTPS-AUTO); 10d PENDING -> PENDING; 20d REJECTED -> REJECTED",
            "actual": f"19d={s10_db[0] if s10_db else 'None'} ({s10_db[1] if s10_db else 'None'}), 10d={s10_recent_db[0] if s10_recent_db else 'None'}, 20d_rejected={s10_rej_db[0] if s10_rej_db else 'None'}",
            "passed": s10_passed,
        },
        "passed": s10_passed,
        "explanation": f"RTPS automated daemon transitioned 19-day overdue application {sla_app_no} to DEEMED_APPROVED, left 10-day application PENDING, and preserved officer's prior REJECTED decision.",
    })

    total = len(results)
    passed = sum(1 for r in results if r["passed"])
    failed = total - passed
    pass_rate = round((passed / total) * 100, 1) if total > 0 else 0

    return {
        "timestamp": eval_timestamp,
        "total": total,
        "passed": passed,
        "failed": failed,
        "pass_rate": pass_rate,
        "scenarios": results,
    }
