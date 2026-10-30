# -*- coding: utf-8 -*-
"""
Model Context Protocol (MCP) Server for Sewa Setu.

Provides two distinct Streamable HTTP MCP endpoints:
1. /mcp/citizen  — for citizen assistants (scope `citizen`)
2. /mcp/officer  — for departmental officer assistants (scope `officer`)

Implements the official Model Context Protocol (protocolVersion: 2024-11-05)
over JSON-RPC 2.0 with streamable HTTP POST and Server-Sent Events (SSE).
"""

import base64
import json
import os
import re
import secrets
import time
from datetime import datetime, timedelta
from urllib.parse import parse_qs, urlparse

import jwt
from flask import Blueprint, Response, current_app, jsonify, request, stream_with_context

import app as portal
import oauth

mcp_bp = Blueprint("mcp", __name__)

MCP_PROTOCOL_VERSION = "2024-11-05"

# ---------------------------------------------------------------------------
# Token extraction & verification
# ---------------------------------------------------------------------------

def _get_bearer_token():
    try:
        from flask import has_request_context
        if not has_request_context():
            return None
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            return auth_header[7:].strip()
        # Fallback to query parameter for EventSource / SSE if needed
        return request.args.get("access_token", "").strip()
    except Exception:
        return None


def authenticate_mcp_request(required_role=None, explicit_token=None):
    """
    Verify bearer token for the MCP endpoint.
    Accepts tokens minted for audience = ISSUER, external issuer, or endpoint URLs.
    Returns (claims, None) if authenticated, or (None, error_dict) if invalid.
    """
    token = explicit_token or _get_bearer_token()
    if not token:
        return None, {
            "code": -32001,
            "message": "Authentication required. Provide 'Authorization: Bearer <access_token>'."
        }

    # Verify RSA JWT signature, audience, issuer, and expiry using the portal's public keys
    kid, priv = oauth.signing_key()
    issuer = oauth.ISSUER.rstrip("/")
    ext_issuer = oauth.get_external_issuer().rstrip("/")
    base_candidates = {issuer, ext_issuer, "http://localhost:3000", "http://localhost:8000"}
    valid_audiences = []
    for base in base_candidates:
        if not base:
            continue
        valid_audiences.extend([
            base,
            base + "/mcp",
            base + "/mcp/citizen",
            base + "/mcp/officer",
        ])

    try:
        claims = jwt.decode(
            token,
            priv.public_key(),
            algorithms=["RS256"],
            audience=valid_audiences,
            issuer=list(base_candidates),
        )
    except jwt.ExpiredSignatureError:
        return None, {"code": -32001, "message": "Token has expired."}
    except jwt.InvalidAudienceError as e:
        return None, {"code": -32001, "message": f"Invalid token audience: {e}"}
    except jwt.InvalidIssuerError as e:
        return None, {"code": -32001, "message": f"Invalid token issuer: {e}"}
    except Exception as e:
        return None, {"code": -32001, "message": f"Token verification failed: {e}"}

    if not claims:
        return None, {"code": -32001, "message": "Invalid token"}

    # Check if long-lived program token has been revoked in the database
    if oauth.is_token_revoked(claims):
        return None, {"code": -32001, "message": "Token has been revoked or expired."}

    role = claims.get("role") or claims.get("scope")
    if required_role and role != required_role:
        return None, {
            "code": -32002,
            "message": f"Access denied: this endpoint requires role '{required_role}', but token has role '{role}'."
        }

    return claims, None


# ---------------------------------------------------------------------------
# Citizen Tools Definition
# ---------------------------------------------------------------------------

CITIZEN_TOOLS = [
    {
        "name": "get_scheme_rules",
        "description": "Retrieve the official statutory rules, eligibility criteria, pension amount, statutory SLA timeline, and recognized administrative blocks of the Purvanchal Old Age Pension Scheme.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
    {
        "name": "check_application_requirements",
        "description": "Check the exact technical fields, document formats, bank account constraints, and IFSC requirements needed to apply for the Old Age Pension Scheme.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
    {
        "name": "submit_application",
        "description": "Submit a complete and validated Old Age Pension application for the authenticated citizen into the official government portal system of record. Enforces statutory age, block eligibility, bank account format, age-proof document attachment, and single active application constraint.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "applicant_name": {
                    "type": "string",
                    "description": "Full legal name of the senior citizen applicant.",
                },
                "dob": {
                    "type": "string",
                    "description": "Date of birth in DD/MM/YYYY format (applicant must be 60 years or older).",
                },
                "gender": {
                    "type": "string",
                    "enum": ["Male", "Female", "Other"],
                    "description": "Gender of the applicant.",
                },
                "marital_status": {
                    "type": "string",
                    "enum": ["Married", "Widowed", "Unmarried", "Divorced"],
                    "description": "Marital status of the applicant.",
                },
                "husband_name": {
                    "type": "string",
                    "description": "Husband's name (if applicant is female and married or widowed).",
                    "default": "",
                },
                "village": {
                    "type": "string",
                    "description": "Name of village or town.",
                },
                "block": {
                    "type": "string",
                    "description": "Recognized development block. Must be one of: Sonari, Rajapara, Dhemaji Pathar, Borgaon, Namti, Khelua.",
                },
                "bank_account": {
                    "type": "string",
                    "description": "Savings bank account number (9 to 18 digits).",
                },
                "ifsc": {
                    "type": "string",
                    "description": "11-character Indian Financial System Code (e.g. SBIN0003077).",
                },
                "document_name": {
                    "type": "string",
                    "description": "Name of the age-proof document file (e.g. voter_id.pdf, aadhaar.jpg).",
                },
                "document_base64": {
                    "type": "string",
                    "description": "Base64-encoded file content of the age-proof document (JPG, PNG, or PDF, max 5 MB).",
                },
            },
            "required": [
                "applicant_name",
                "dob",
                "gender",
                "marital_status",
                "village",
                "block",
                "bank_account",
                "ifsc",
            ],
            "additionalProperties": False,
        },
    },
    {
        "name": "get_application_status",
        "description": "Check the live status and processing history of the authenticated citizen's pension application in the government portal database.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "application_no": {
                    "type": "string",
                    "description": "Optional specific application number (e.g. SSP26100101). If omitted, retrieves the citizen's latest application.",
                }
            },
            "additionalProperties": False,
        },
    },
]


# ---------------------------------------------------------------------------
# Officer Tools Definition
# ---------------------------------------------------------------------------

OFFICER_TOOLS = [
    {
        "name": "list_pending_applications",
        "description": "List applications currently in PENDING status awaiting block officer verification, sorted by statutory submission date.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "block": {
                    "type": "string",
                    "description": "Optional filter by block (e.g. Sonari, Rajapara, Dhemaji Pathar, Borgaon, Namti, Khelua).",
                },
                "page": {
                    "type": "integer",
                    "description": "Page number (1-based, default 1).",
                    "default": 1,
                },
                "limit": {
                    "type": "integer",
                    "description": "Number of cases per page (default 20, max 50).",
                    "default": 20,
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "get_application_details",
        "description": "Inspect the complete dossier of an application including personal details, address, bank particulars, age-proof document path, current status, and complete chronological audit log.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "application_id": {
                    "type": "integer",
                    "description": "Internal database ID of the application (e.g. 1).",
                },
                "application_no": {
                    "type": "string",
                    "description": "Government application reference number (e.g. SSP26100101).",
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "approve_application",
        "description": "Record an official departmental APPROVE decision on a pending pension application. Enforces that the case is currently PENDING, updates the database state, and records the officer's identity and verification remarks in the immutable audit trail.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "application_id": {
                    "type": "integer",
                    "description": "Internal database ID of the application.",
                },
                "application_no": {
                    "type": "string",
                    "description": "Government application reference number (e.g. SSP26100101).",
                },
                "note": {
                    "type": "string",
                    "description": "Mandatory or recommended verification note (e.g. 'Age proof verified against electoral roll; bank account validated').",
                    "default": "Approved by block officer after statutory verification",
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "reject_application",
        "description": "Record an official departmental REJECT decision on a pending pension application. Enforces that the case is currently PENDING, updates the database state to REJECTED, and logs the statutory grounds for rejection in the audit trail.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "application_id": {
                    "type": "integer",
                    "description": "Internal database ID of the application.",
                },
                "application_no": {
                    "type": "string",
                    "description": "Government application reference number (e.g. SSP26100101).",
                },
                "reason": {
                    "type": "string",
                    "description": "Specific statutory reason for rejection (e.g. 'Ineligible age: applicant under 60 years' or 'Address outside administrative block').",
                },
            },
            "required": ["reason"],
            "additionalProperties": False,
        },
    },
    {
        "name": "get_decision_result",
        "description": "Retrieve the official recorded decision, timestamp, deciding officer, and audit trail for a processed application.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "application_id": {
                    "type": "integer",
                    "description": "Internal database ID of the application.",
                },
                "application_no": {
                    "type": "string",
                    "description": "Government application reference number (e.g. SSP26100101).",
                },
            },
            "additionalProperties": False,
        },
    },
]


# ---------------------------------------------------------------------------
# Tool Execution Logic
# ---------------------------------------------------------------------------

def execute_citizen_tool(name, args, claims):
    mobile = None
    if claims and claims.get("sub", "").startswith("citizen:"):
        mobile = claims["sub"].split(":", 1)[1]

    if name == "get_scheme_rules":
        deadline_str = portal.SCHEME_DEADLINE.strftime("%Y-%m-%d %H:%M IST")
        hours_remaining = portal.deadline_remaining()
        return {
            "scheme_name": "Old Age Pension Scheme",
            "department": "Department of Social Welfare, Government of Purvanchal",
            "monthly_pension": "Rs. 250",
            "minimum_age": portal.MIN_AGE,
            "statutory_sla_days": portal.SLA_DAYS,
            "scheme_deadline": deadline_str,
            "is_window_open": hours_remaining is not None,
            "hours_remaining": hours_remaining,
            "supported_blocks": portal.BLOCKS,
            "block_villages": portal.BLOCK_VILLAGES,
            "eligible_districts": "Purvanchal State",
            "required_documents": [
                "Age proof document (Voter ID, Aadhaar, Birth Certificate, or School Certificate in JPG, PNG, or PDF format, max 5 MB)"
            ],
            "rules": [
                "Applicant must be a senior citizen aged 60 years or above.",
                "Applicant must reside in one of the 6 recognized development blocks: " + ", ".join(portal.BLOCKS) + ".",
                "Valid bank account number (9 to 18 digits) and 11-character IFSC must be provided.",
                "Only one active application (PENDING, APPROVED, or DEEMED_APPROVED) is permitted per mobile number.",
                "Under the Purvanchal Right to Public Services (RTPS) Act, any application not decided within 15 days is deemed approved."
            ],
        }

    elif name == "check_application_requirements":
        return {
            "mandatory_fields": [
                {"field": "applicant_name", "type": "string", "description": "Full legal name"},
                {"field": "dob", "type": "string", "format": "DD/MM/YYYY", "rule": f"Must be >= {portal.MIN_AGE} years of age"},
                {"field": "gender", "type": "string", "allowed_values": ["Male", "Female", "Other"]},
                {"field": "marital_status", "type": "string", "allowed_values": ["Married", "Widowed", "Unmarried", "Divorced"]},
                {"field": "village", "type": "string", "description": "Village or locality name belonging to the selected block", "mapped_by_block": portal.BLOCK_VILLAGES},
                {"field": "block", "type": "string", "allowed_values": portal.BLOCKS},
                {"field": "bank_account", "type": "string", "format": "9 to 18 digits without hyphens/spaces"},
                {"field": "ifsc", "type": "string", "format": "11-character code matching ^[A-Z]{4}0[A-Z0-9]{6}$"},
            ],
            "document_requirements": {
                "allowed_extensions": ["pdf", "jpg", "jpeg", "png"],
                "max_size_bytes": 5 * 1024 * 1024,
                "max_size_mb": 5,
                "description": "Age-proof document verifying date of birth"
            },
            "submission_constraints": {
                "active_statuses_blocking_new_application": list(portal.ACTIVE_STATUSES),
                "scheme_window_deadline": portal.SCHEME_DEADLINE.strftime("%Y-%m-%d %H:%M IST")
            }
        }

    elif name == "submit_application":
        if not mobile:
            raise ValueError("Authentication required. Citizen mobile not found in token.")

        # Document handling: enforce identical rules to the web portal (/upload)
        doc_path = ""
        doc_b64 = (args.get("document_base64") or "").strip()
        raw_doc_name = (args.get("document_name") or "").strip()
        doc_Content = None

        if doc_b64:
            if not raw_doc_name:
                raw_doc_name = "age_proof.pdf"
            safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(raw_doc_name))
            doc_ext = safe_name.rsplit(".", 1)[-1].lower() if "." in safe_name else ""
            if doc_ext not in ("pdf", "jpg", "jpeg", "png"):
                raise ValueError("Validation failed: age proof document must be a JPG, PNG, or PDF file.")

            try:
                if "," in doc_b64:
                    doc_b64 = doc_b64.split(",", 1)[1]
                doc_Content = base64.b64decode(doc_b64, validate=True)
            except Exception as e:
                raise ValueError(f"Validation failed: invalid base64 age-proof document ({e}).")

            if not doc_Content:
                raise ValueError("Validation failed: age proof document is empty.")
            if len(doc_Content) > 5 * 1024 * 1024:
                raise ValueError("Validation failed: age proof document exceeds the 5 MB limit.")

            os.makedirs(portal.UPLOAD_DIR, exist_ok=True)
            filename = f"{mobile}_{int(time.time())}_{safe_name}"
            doc_path = os.path.join(portal.UPLOAD_DIR, filename)

        # Validate application using portal's canonical rules (requires non-empty doc_path)
        errors, cleaned = portal.validate_application(args, doc_path)
        if errors:
            raise ValueError("Validation failed: " + "; ".join(errors))

        # Check existing active application before writing file or inserting
        conn = portal.get_db()
        cur = conn.cursor()
        existing = portal.active_application(cur, mobile)
        if existing:
            cur.close(); conn.close()
            raise ValueError(
                f"Application {existing[1]} ({existing[2]}) already exists for mobile {mobile}. "
                "Only one active application is permitted."
            )

        # Persist verified document to disk
        if doc_path and doc_Content is not None:
            with open(doc_path, "wb") as f:
                f.write(doc_Content)

        new_id, app_no = portal.create_application(cur, mobile, cleaned)
        conn.commit()
        cur.close(); conn.close()

        # Send portal confirmation notification
        portal.send_sms(
            mobile,
            f"Sewa Setu: application {app_no} received. Track at the status portal with mobile no. and DOB (DDMMYYYY)."
        )

        ext_base = oauth.get_external_issuer()
        return {
            "success": True,
            "application_no": app_no,
            "application_id": new_id,
            "status": "PENDING",
            "applicant_name": cleaned["applicant_name"],
            "mobile": mobile,
            "submitted_at": datetime.now().isoformat(),
            "message": f"Application {app_no} successfully submitted and registered in Sewa Setu.",
            "tracking_url": f"{ext_base}/status",
        }

    elif name == "get_application_status":
        if not mobile:
            raise ValueError("Authentication required. Citizen mobile not found in token.")

        app_no = args.get("application_no", "").strip()
        conn = portal.get_db()
        cur = conn.cursor()
        if app_no:
            cur.execute(
                """SELECT id, application_no, applicant_name, dob, village, block,
                          bank_account, ifsc, status, submitted_at, decided_at, decided_by
                   FROM applications WHERE application_no = %s AND mobile = %s""",
                (app_no, mobile)
            )
        else:
            cur.execute(
                """SELECT id, application_no, applicant_name, dob, village, block,
                          bank_account, ifsc, status, submitted_at, decided_at, decided_by
                   FROM applications WHERE mobile = %s ORDER BY submitted_at DESC LIMIT 1""",
                (mobile,)
            )
        row = cur.fetchone()
        if not row:
            cur.close(); conn.close()
            return {
                "found": False,
                "mobile": mobile,
                "message": "No application found for this citizen."
            }

        app_id = row[0]
        cur.execute(
            "SELECT action, actor, note, at FROM audit_log WHERE application_id = %s ORDER BY at ASC",
            (app_id,)
        )
        audit_rows = cur.fetchall()
        cur.close(); conn.close()

        audit_history = [
            {
                "action": a[0],
                "actor": a[1],
                "note": a[2] or "",
                "at": a[3].isoformat() if hasattr(a[3], "isoformat") else str(a[3]),
            }
            for a in audit_rows
        ]

        submitted_at_val = row[9]
        days_pending = None
        if submitted_at_val and isinstance(submitted_at_val, datetime):
            days_pending = (datetime.now() - submitted_at_val).days

        return {
            "found": True,
            "application_id": row[0],
            "application_no": row[1],
            "applicant_name": row[2],
            "dob": row[3].isoformat() if hasattr(row[3], "isoformat") else str(row[3]),
            "village": row[4],
            "block": row[5],
            "status": row[8],
            "submitted_at": submitted_at_val.isoformat() if hasattr(submitted_at_val, "isoformat") else str(submitted_at_val),
            "days_pending": days_pending,
            "decided_at": row[10].isoformat() if row[10] and hasattr(row[10], "isoformat") else (str(row[10]) if row[10] else None),
            "decided_by": row[11],
            "audit_history": audit_history,
        }

    else:
        raise ValueError(f"Unknown citizen tool: {name}")


def execute_officer_tool(name, args, claims):
    officer_name = portal.ADMIN_USERNAME
    if claims and claims.get("sub", "").startswith("officer:"):
        officer_name = claims["sub"].split(":", 1)[1]

    if name == "list_pending_applications":
        block_filter = args.get("block", "").strip()
        page = max(1, int(args.get("page", 1)))
        limit = min(50, max(1, int(args.get("limit", 20))))
        offset = (page - 1) * limit

        conn = portal.get_db()
        cur = conn.cursor()
        if block_filter:
            cur.execute(
                """SELECT id, application_no, applicant_name, mobile, block, village, submitted_at
                   FROM applications
                   WHERE status = 'PENDING' AND block = %s
                   ORDER BY submitted_at ASC LIMIT %s OFFSET %s""",
                (block_filter, limit, offset)
            )
        else:
            cur.execute(
                """SELECT id, application_no, applicant_name, mobile, block, village, submitted_at
                   FROM applications
                   WHERE status = 'PENDING'
                   ORDER BY submitted_at ASC LIMIT %s OFFSET %s""",
                (limit, offset)
            )
        rows = cur.fetchall()

        cur.execute("SELECT count(*) FROM applications WHERE status = 'PENDING'")
        total_pending = cur.fetchone()[0]
        cur.close(); conn.close()

        now = datetime.now()
        cases = []
        for r in rows:
            sub_dt = r[6]
            days_pending = (now - sub_dt).days if isinstance(sub_dt, datetime) else 0
            is_overdue = days_pending >= portal.SLA_DAYS
            cases.append({
                "application_id": r[0],
                "application_no": r[1],
                "applicant_name": r[2],
                "mobile": r[3],
                "block": r[4],
                "village": r[5],
                "submitted_at": sub_dt.isoformat() if hasattr(sub_dt, "isoformat") else str(sub_dt),
                "days_pending": days_pending,
                "sla_days_total": portal.SLA_DAYS,
                "is_sla_overdue": is_overdue,
            })

        return {
            "total_pending_all_blocks": total_pending,
            "filter_block": block_filter or "all",
            "page": page,
            "count": len(cases),
            "applications": cases,
        }

    elif name == "get_application_details":
        app_id = args.get("application_id")
        app_no = args.get("application_no", "").strip()
        if not app_id and not app_no:
            raise ValueError("Either 'application_id' or 'application_no' must be provided.")

        conn = portal.get_db()
        cur = conn.cursor()
        if app_id:
            cur.execute(
                """SELECT id, application_no, applicant_name, mobile, dob, gender, marital_status,
                          husband_name, village, block, bank_account, ifsc, doc_path, status,
                          submitted_at, decided_at, decided_by
                   FROM applications WHERE id = %s""",
                (int(app_id),)
            )
        else:
            cur.execute(
                """SELECT id, application_no, applicant_name, mobile, dob, gender, marital_status,
                          husband_name, village, block, bank_account, ifsc, doc_path, status,
                          submitted_at, decided_at, decided_by
                   FROM applications WHERE application_no = %s""",
                (app_no,)
            )
        row = cur.fetchone()
        if not row:
            cur.close(); conn.close()
            raise ValueError(f"Application not found with id={app_id} or no={app_no}.")

        actual_id = row[0]
        cur.execute(
            "SELECT action, actor, note, at FROM audit_log WHERE application_id = %s ORDER BY at ASC",
            (actual_id,)
        )
        audit_rows = cur.fetchall()
        cur.close(); conn.close()

        now = datetime.now()
        sub_dt = row[14]
        days_pending = (now - sub_dt).days if isinstance(sub_dt, datetime) else 0

        return {
            "application_id": row[0],
            "application_no": row[1],
            "applicant_name": row[2],
            "mobile": row[3],
            "dob": row[4].isoformat() if hasattr(row[4], "isoformat") else str(row[4]),
            "gender": row[5],
            "marital_status": row[6],
            "husband_name": row[7] or "",
            "village": row[8],
            "block": row[9],
            "bank_account": row[10],
            "ifsc": row[11],
            "document_filename": os.path.basename(row[12]) if row[12] else None,
            "document_attached": bool(row[12] and os.path.exists(row[12])),
            "status": row[13],
            "submitted_at": sub_dt.isoformat() if hasattr(sub_dt, "isoformat") else str(sub_dt),
            "days_pending": days_pending,
            "decided_at": row[15].isoformat() if row[15] and hasattr(row[15], "isoformat") else (str(row[15]) if row[15] else None),
            "decided_by": row[16],
            "audit_trail": [
                {
                    "action": a[0],
                    "actor": a[1],
                    "note": a[2] or "",
                    "timestamp": a[3].isoformat() if hasattr(a[3], "isoformat") else str(a[3]),
                }
                for a in audit_rows
            ],
        }

    elif name == "approve_application":
        app_id = args.get("application_id")
        app_no = args.get("application_no", "").strip()
        note = (args.get("note") or "Approved by block officer after verification").strip()
        if not app_id and not app_no:
            raise ValueError("Either 'application_id' or 'application_no' is required.")

        conn = portal.get_db()
        cur = conn.cursor()
        # Fetch current record
        if app_id:
            cur.execute("SELECT id, application_no, status, mobile FROM applications WHERE id = %s", (int(app_id),))
        else:
            cur.execute("SELECT id, application_no, status, mobile FROM applications WHERE application_no = %s", (app_no,))
        row = cur.fetchone()
        if not row:
            cur.close(); conn.close()
            raise ValueError(f"Application not found.")

        target_id, target_no, current_status, mobile = row
        if current_status != "PENDING":
            cur.close(); conn.close()
            raise ValueError(
                f"Application {target_no} is currently in status '{current_status}'. Only PENDING applications can be decided."
            )

        decided_at = datetime.now()
        cur.execute(
            """UPDATE applications
               SET status = 'APPROVED', decided_at = %s, decided_by = %s
               WHERE id = %s AND status = 'PENDING' RETURNING application_no""",
            (decided_at, officer_name, target_id)
        )
        updated = cur.fetchone()
        if not updated:
            cur.close(); conn.close()
            raise ValueError("Failed to update status. Application may have been modified concurrently.")

        portal.write_audit(cur, target_id, "APPROVED", f"officer:{officer_name}", note)
        conn.commit()
        cur.close(); conn.close()

        # Send decision notification via SMS gateway
        portal.send_sms(
            mobile,
            f"Sewa Setu: your pension application {target_no} has been APPROVED by the block office."
        )

        return {
            "success": True,
            "application_id": target_id,
            "application_no": target_no,
            "status": "APPROVED",
            "decided_by": officer_name,
            "decided_at": decided_at.isoformat(),
            "note": note,
            "message": f"Application {target_no} has been successfully approved.",
        }

    elif name == "reject_application":
        app_id = args.get("application_id")
        app_no = args.get("application_no", "").strip()
        reason = (args.get("reason") or "").strip()
        if not reason:
            raise ValueError("A specific reason for rejection is mandatory.")
        if not app_id and not app_no:
            raise ValueError("Either 'application_id' or 'application_no' is required.")

        conn = portal.get_db()
        cur = conn.cursor()
        if app_id:
            cur.execute("SELECT id, application_no, status, mobile FROM applications WHERE id = %s", (int(app_id),))
        else:
            cur.execute("SELECT id, application_no, status, mobile FROM applications WHERE application_no = %s", (app_no,))
        row = cur.fetchone()
        if not row:
            cur.close(); conn.close()
            raise ValueError("Application not found.")

        target_id, target_no, current_status, mobile = row
        if current_status != "PENDING":
            cur.close(); conn.close()
            raise ValueError(
                f"Application {target_no} is currently '{current_status}'. Only PENDING applications can be rejected."
            )

        decided_at = datetime.now()
        cur.execute(
            """UPDATE applications
               SET status = 'REJECTED', decided_at = %s, decided_by = %s
               WHERE id = %s AND status = 'PENDING' RETURNING application_no""",
            (decided_at, officer_name, target_id)
        )
        updated = cur.fetchone()
        if not updated:
            cur.close(); conn.close()
            raise ValueError("Failed to update status. Case may have been modified concurrently.")

        portal.write_audit(cur, target_id, "REJECTED", f"officer:{officer_name}", reason)
        conn.commit()
        cur.close(); conn.close()

        portal.send_sms(
            mobile,
            f"Sewa Setu: your pension application {target_no} was not approved. Reason: {reason}."
        )

        return {
            "success": True,
            "application_id": target_id,
            "application_no": target_no,
            "status": "REJECTED",
            "decided_by": officer_name,
            "decided_at": decided_at.isoformat(),
            "reason": reason,
            "message": f"Application {target_no} has been rejected.",
        }

    elif name == "get_decision_result":
        app_id = args.get("application_id")
        app_no = args.get("application_no", "").strip()
        if not app_id and not app_no:
            raise ValueError("Either 'application_id' or 'application_no' is required.")

        conn = portal.get_db()
        cur = conn.cursor()
        if app_id:
            cur.execute(
                """SELECT id, application_no, applicant_name, status, decided_at, decided_by
                   FROM applications WHERE id = %s""",
                (int(app_id),)
            )
        else:
            cur.execute(
                """SELECT id, application_no, applicant_name, status, decided_at, decided_by
                   FROM applications WHERE application_no = %s""",
                (app_no,)
            )
        row = cur.fetchone()
        if not row:
            cur.close(); conn.close()
            raise ValueError("Application not found.")

        target_id = row[0]
        cur.execute(
            "SELECT action, actor, note, at FROM audit_log WHERE application_id = %s ORDER BY at DESC",
            (target_id,)
        )
        audit_rows = cur.fetchall()
        cur.close(); conn.close()

        return {
            "application_id": row[0],
            "application_no": row[1],
            "applicant_name": row[2],
            "status": row[3],
            "decided_at": row[4].isoformat() if row[4] and hasattr(row[4], "isoformat") else (str(row[4]) if row[4] else None),
            "decided_by": row[5],
            "latest_audit": [
                {
                    "action": a[0],
                    "actor": a[1],
                    "note": a[2] or "",
                    "at": a[3].isoformat() if hasattr(a[3], "isoformat") else str(a[3]),
                }
                for a in audit_rows[:5]
            ],
        }

    else:
        raise ValueError(f"Unknown officer tool: {name}")


# ---------------------------------------------------------------------------
# JSON-RPC 2.0 Dispatcher for MCP
# ---------------------------------------------------------------------------

def handle_mcp_rpc(payload, role, auth_token=None):
    """Process a single JSON-RPC 2.0 message."""
    if not isinstance(payload, dict):
        return {
            "jsonrpc": "2.0",
            "id": None,
            "error": {"code": -32600, "message": "Invalid Request: expected JSON object"},
        }

    msg_id = payload.get("id")
    method = payload.get("method")
    params = payload.get("params") or {}

    # Notification check (no id)
    is_notification = msg_id is None

    # 1. Initialize
    if method == "initialize":
        server_name = f"sewasetu-{role}-mcp"
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {
                    "tools": {"listChanged": False},
                },
                "serverInfo": {
                    "name": server_name,
                    "version": "1.0.0",
                    "description": f"Sewa Setu Government Pension Portal - {role.capitalize()} Assistant MCP Server",
                },
            },
        }

    # 2. Initialized notification
    if method == "notifications/initialized":
        return None

    # 3. Ping
    if method == "ping":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {}}

    # 4. Tools list
    if method == "tools/list":
        # Check authentication if officer, or allow discovery
        if role == "officer":
            claims, err = authenticate_mcp_request(required_role="officer", explicit_token=auth_token)
            if err:
                return {"jsonrpc": "2.0", "id": msg_id, "error": err}
            return {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": OFFICER_TOOLS}}
        else:
            # Citizen tools can be discovered or listed
            return {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": CITIZEN_TOOLS}}

    # 5. Tools call
    if method == "tools/call":
        tool_name = params.get("name")
        tool_args = params.get("arguments") or {}

        # Informational tools on the citizen endpoint can be invoked publicly
        if role == "citizen" and tool_name in ("get_scheme_rules", "check_application_requirements"):
            claims, _ = authenticate_mcp_request(required_role="citizen", explicit_token=auth_token)
        else:
            claims, err = authenticate_mcp_request(required_role=role, explicit_token=auth_token)
            if err:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": err,
                }

        try:
            if role == "citizen":
                res = execute_citizen_tool(tool_name, tool_args, claims)
            else:
                res = execute_officer_tool(tool_name, tool_args, claims)

            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(res, indent=2, ensure_ascii=False),
                        }
                    ],
                    "isError": False,
                },
            }
        except Exception as e:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "content": [{"type": "text", "text": f"Error: {str(e)}"}],
                    "isError": True,
                },
            }

    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "error": {"code": -32601, "message": f"Method '{method}' not found"},
    }


# ---------------------------------------------------------------------------
# HTTP & SSE Route Handlers
# ---------------------------------------------------------------------------

def _mcp_endpoint_handler(role):
    # Support CORS Preflight
    if request.method == "OPTIONS":
        return Response(
            "",
            status=204,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                "Access-Control-Allow-Headers": "Authorization, Content-Type, Accept",
            },
        )

    # GET request: Info / SSE initiation
    if request.method == "GET":
        ext_base = oauth.get_external_issuer()
        accept_header = request.headers.get("Accept", "")
        if "text/event-stream" in accept_header:
            session_id = secrets.token_hex(12)
            endpoint_url = f"{ext_base}/mcp/{role}/messages?session_id={session_id}"

            def sse_stream():
                # Emit endpoint event per MCP SSE transport spec, then close.
                # Do NOT loop forever — that blocks a Gunicorn sync worker permanently.
                # Clients reconnect automatically (EventSource retry behaviour).
                yield f"event: endpoint\ndata: {endpoint_url}\n\n"

            resp = Response(
                stream_with_context(sse_stream()),
                content_type="text/event-stream",
                headers={
                    "Cache-Control": "no-cache",
                    "Connection": "close",
                    "Access-Control-Allow-Origin": "*",
                },
            )
            return resp

        # Return discovery / status info
        tools = CITIZEN_TOOLS if role == "citizen" else OFFICER_TOOLS
        return jsonify({
            "service": f"Sewa Setu {role.capitalize()} MCP Server",
            "protocol": "Model Context Protocol",
            "version": MCP_PROTOCOL_VERSION,
            "role_required": role,
            "transport": ["Streamable HTTP POST", "Server-Sent Events (SSE)"],
            "endpoints": {
                "post": f"{ext_base}/mcp/{role}",
                "sse": f"{ext_base}/mcp/{role}",
            },
            "oauth_discovery": f"{ext_base}/.well-known/oauth-authorization-server",
            "available_tools": [t["name"] for t in tools],
        })

    # POST request: Streamable HTTP JSON-RPC
    data = request.get_json(silent=True)
    if data is None:
        try:
            data = json.loads(request.get_data(as_text=True))
        except Exception:
            return jsonify({
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": "Parse error: invalid JSON"},
            }), 400

    # Batch or single JSON-RPC
    if isinstance(data, list):
        responses = [handle_mcp_rpc(item, role) for item in data]
        filtered = [r for r in responses if r is not None]
        return jsonify(filtered)

    result = handle_mcp_rpc(data, role)
    if result is None:
        return ("", 204)

    # Check if client asked for SSE stream in POST response
    if "text/event-stream" in request.headers.get("Accept", ""):
        def stream_response():
            yield f"event: message\ndata: {json.dumps(result)}\n\n"
        return Response(
            stream_with_context(stream_response()),
            content_type="text/event-stream",
            headers={"Access-Control-Allow-Origin": "*"},
        )

    resp = jsonify(result)
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp


@mcp_bp.route("/mcp/citizen", methods=["GET", "POST", "OPTIONS"])
def mcp_citizen():
    return _mcp_endpoint_handler("citizen")


@mcp_bp.route("/mcp/officer", methods=["GET", "POST", "OPTIONS"])
def mcp_officer():
    return _mcp_endpoint_handler("officer")


@mcp_bp.route("/mcp/citizen/messages", methods=["POST", "OPTIONS"])
def mcp_citizen_messages():
    return _mcp_endpoint_handler("citizen")


@mcp_bp.route("/mcp/officer/messages", methods=["POST", "OPTIONS"])
def mcp_officer_messages():
    return _mcp_endpoint_handler("officer")
