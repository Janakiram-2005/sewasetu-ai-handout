# -*- coding: utf-8 -*-
"""
Sewa Setu - Old Age Pension Portal
Government of Purvanchal, Department of Social Welfare

Developed by: Netlink Infosolutions Pvt Ltd (2023)
Maintained in-house since 02/2026.
"""

import os
import io
import re
import random
import hashlib
import configparser
from datetime import datetime, date, timedelta
from zoneinfo import ZoneInfo

IST = ZoneInfo("Asia/Kolkata")


def now_ist():
    """The portal's clock is Indian Standard Time regardless of where the server runs."""
    return datetime.now(IST).replace(tzinfo=None)

import requests
from flask import (Flask, request, session, redirect, url_for, render_template,
                   flash, send_file, abort)
try:
    from flask_wtf.csrf import CSRFProtect
except ImportError:
    class CSRFProtect:
        def __init__(self, app=None): pass
        def exempt(self, view): return view
from fpdf import FPDF

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

config = configparser.ConfigParser()
config.read(os.path.join(BASE_DIR, "config", "app.ini"))

from db_compat import connect_db, is_production_env

_INSECURE_SECRET_KEYS = {
    "",
    "ssp-prod-key-2023-donotshare",
    "dev-local-only-override-with-env",
    "change-me",
    "change-me-before-deploying",
}
_INSECURE_ADMIN_PASSWORDS = {
    "",
    "change-me-before-deploying",
    "sewasetu123",
    "admin",
    "password",
}

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or config.get("app", "secret_key")
# Two hours: elderly applicants fill the form slowly; the draft lives in the session.
app.config["PERMANENT_SESSION_LIFETIME"] = 7200
# WTF CSRF — API blueprints (OAuth, MCP) are exempted explicitly after registration.
app.config["WTF_CSRF_TIME_LIMIT"] = 7200  # match session lifetime
csrf = CSRFProtect(app)

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
PUBLIC_BASE_URL = (
    os.environ.get("PUBLIC_BASE_URL")
    or os.environ.get("RENDER_EXTERNAL_URL")
    or "http://localhost:3000"
).rstrip("/")


def validate_production_config():
    """Verify required production secrets and database configuration when running in production."""
    if not is_production_env():
        return
    missing_or_weak = []
    env_secret = (os.environ.get("SECRET_KEY") or "").strip()
    if not env_secret or env_secret in _INSECURE_SECRET_KEYS:
        missing_or_weak.append("SECRET_KEY (must be set to a strong non-default secret)")
    env_admin_pw = (os.environ.get("ADMIN_PASSWORD") or "").strip()
    if not env_admin_pw or env_admin_pw in _INSECURE_ADMIN_PASSWORDS:
        missing_or_weak.append("ADMIN_PASSWORD (must be set to a strong non-default password)")
    env_db_url = (os.environ.get("DATABASE_URL") or "").strip()
    if not env_db_url:
        missing_or_weak.append("DATABASE_URL (required in production; SQLite fallback is disabled)")
    if missing_or_weak:
        raise RuntimeError(
            "Unsafe production configuration — missing or insecure environment variables: "
            + ", ".join(missing_or_weak)
        )


validate_production_config()

# An applicant may hold at most one application in these states at a time.
# WITHDRAWN and REJECTED applications do not block a fresh application.
ACTIVE_STATUSES = ("PENDING", "APPROVED", "DEEMED_APPROVED")

SMS_GATEWAY_URL = (
    os.environ.get("SMS_GATEWAY_URL")
    if "SMS_GATEWAY_URL" in os.environ
    else ("" if is_production_env() else config.get("app", "sms_gateway_url", fallback=""))
)
OTP_VALIDITY_SECONDS = config.getint("app", "otp_validity_seconds")
UPLOAD_DIR = os.environ.get("UPLOAD_DIR") or config.get("app", "upload_dir")
SCHEME_DEADLINE = datetime.strptime(config.get("pension", "scheme_deadline"),
                                    "%Y-%m-%d %H:%M")
MIN_AGE = config.getint("pension", "min_age")
SLA_DAYS = config.getint("pension", "sla_days")

BLOCKS = ["Sonari", "Rajapara", "Dhemaji Pathar", "Borgaon", "Namti", "Khelua"]

# Village/Town-to-Block mappings strictly derived from the supplied project
# materials (seed data in db_compat.py, database snapshot, evaluation personas,
# and regression suite). Because the project materials only specify a subset of
# villages per Purvanchal block, a clearly labelled manual-entry fallback
# ("__OTHER__") is supported while preventing cross-block village mismatches.
BLOCK_VILLAGES = {
    "Sonari": ["Disangmukh", "Sonari Gaon", "Sonari Town"],
    "Rajapara": ["Boko Bazar", "Boko", "Rajapara"],
    "Dhemaji Pathar": ["Silapathar"],
    "Borgaon": ["Barpeta Road", "Borgaon Bazar"],
    "Namti": ["Amguri", "Namti Chariali"],
    "Khelua": ["Sivasagar Chariali", "Khelua Gaon"],
}

_VILLAGE_TO_BLOCK = {
    v.lower(): b
    for b, villages in BLOCK_VILLAGES.items()
    for v in villages
}
_CANONICAL_VILLAGES = {
    v.lower(): v
    for villages in BLOCK_VILLAGES.values()
    for v in villages
}


import logging
_logdir = "/var/log/sewasetu"
try:
    os.makedirs(_logdir, exist_ok=True)
    _fh = logging.FileHandler(os.path.join(_logdir, "sewasetu-app.log"))
    _fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s in app: %(message)s"))
    app.logger.addHandler(_fh)
    app.logger.setLevel(logging.INFO)
except Exception:
    pass


def is_demo_otp_enabled():
    """Return True if session-scoped demo OTP display is enabled (default True for student demo)."""
    return os.environ.get("DEMO_OTP_DISPLAY", "1").strip().lower() not in ("0", "false", "no", "off")


def is_gateway_console_enabled():
    """Return True only when admin gateway console is explicitly enabled in non-production."""
    if is_production_env():
        return False
    return os.environ.get("ALLOW_ADMIN_GATEWAY_CONSOLE", "0").strip().lower() in ("1", "true", "yes")


def get_db():
    return connect_db(config)


def sanitize(value, maxlen=100):
    # Trim whitespace and cap at the column width, counting characters (not
    # bytes) so Assamese/Bangla names are stored intact.
    if value is None:
        return ""
    return value.strip()[:maxlen]


def hash_password(p):
    return hashlib.sha256(p.encode("utf-8")).hexdigest()


def send_sms(mobile, text):
    gw_url = (SMS_GATEWAY_URL or "").strip()
    if not gw_url or gw_url.lower() in ("none", "disabled", "off"):
        return
    try:
        requests.post(gw_url.rstrip("/") + "/api/send",
                      json={"to": mobile, "text": text}, timeout=3)
    except Exception:
        # Never log SMS text or OTP contents to application logs.
        app.logger.warning("sms gateway delivery skipped (gateway unreachable)")


def deadline_remaining():
    delta = SCHEME_DEADLINE - now_ist()
    if delta.total_seconds() <= 0:
        return None
    return int(delta.total_seconds() // 3600)


def new_application_no():
    # Use IST clock so year suffix in application numbers is always India-correct.
    return "SSP" + now_ist().strftime("%y") + str(random.randint(100000, 999999))


def write_audit(cur, app_id, action, actor, note=""):
    cur.execute("INSERT INTO audit_log (application_id, action, actor, note, at) "
                "VALUES (%s, %s, %s, %s, %s)",
                (app_id, action, actor, note, now_ist()))


# ---------------------------------------------------------------------------
# Scheme rules: the single source of truth for what an application must satisfy.
# Every channel that creates an application (the web form, any API, any batch
# import) MUST go through validate_application() and create_application() so
# that no channel admits an application another channel would refuse.
# ---------------------------------------------------------------------------

def parse_dob(raw):
    try:
        return datetime.strptime((raw or "").strip(), "%d/%m/%Y").date()
    except ValueError:
        return None


def age_on(dob, on):
    return on.year - dob.year - ((on.month, on.day) < (dob.month, dob.day))


def resolve_and_validate_location(raw_block, raw_village, raw_village_other="", require_mapped_unless_other=False):
    """Resolve and validate (block, village) selection and parent-child relationship.

    Returns (errors, cleaned_block, cleaned_village).
    """
    loc_errors = []
    block = (raw_block or "").strip()
    v_sel = (raw_village or "").strip()
    v_other = sanitize(raw_village_other)

    is_other_mode = (v_sel == "__OTHER__")
    if is_other_mode:
        village = v_other
    else:
        village = sanitize(v_sel)

    if village.lower() in _CANONICAL_VILLAGES:
        village = _CANONICAL_VILLAGES[village.lower()]

    if not village:
        loc_errors.append("village is required")
    if not block:
        loc_errors.append("block is required")
    elif block not in BLOCKS:
        loc_errors.append("block must be one of: " + ", ".join(BLOCKS))
    elif village:
        expected_block = _VILLAGE_TO_BLOCK.get(village.lower())
        if expected_block and expected_block != block:
            loc_errors.append(
                "village '%s' belongs to block '%s', not '%s'"
                % (village, expected_block, block)
            )
        elif require_mapped_unless_other and not is_other_mode:
            if village not in BLOCK_VILLAGES.get(block, []):
                loc_errors.append(
                    "village '%s' is not in the mapped list for block '%s'; "
                    "select a mapped village or choose 'Other (enter manually)'"
                    % (village, block)
                )

    return loc_errors, block, village


def validate_application(data, doc_path):
    """Validate a complete application. Returns (errors, cleaned).

    `errors` is a list of plain-language problems (empty when valid);
    `cleaned` holds the normalised values ready for create_application().
    """
    errors = []
    loc_errors, c_block, c_village = resolve_and_validate_location(
        data.get("block"),
        data.get("village"),
        data.get("village_other", ""),
        require_mapped_unless_other=(data.get("location_dropdown_mode") == "1"),
    )
    cleaned = {
        "applicant_name": sanitize(data.get("applicant_name")),
        "village": c_village,
        "block": c_block,
        "gender": data.get("gender") or "",
        "marital_status": data.get("marital_status") or "",
        "husband_name": (data.get("husband_name") or "").strip(),
        "husband_employer": "",  # no longer collected (not a scheme requirement)
        "bank_account": re.sub(r"[\s-]", "", data.get("bank_account") or ""),
        "ifsc": re.sub(r"[\s-]", "", (data.get("ifsc") or "")).upper(),
        "doc_path": doc_path or "",
        "dob": None,
    }
    if not cleaned["applicant_name"]:
        errors.append("full name is required")
    errors.extend(loc_errors)
    if not cleaned["bank_account"]:
        errors.append("bank account is required")
    if cleaned["bank_account"] and not re.fullmatch(r"\d{9,18}", cleaned["bank_account"]):
        errors.append("bank account number must be 9 to 18 digits")
    if cleaned["ifsc"] and not re.fullmatch(r"[A-Z]{4}0[A-Z0-9]{6}", cleaned["ifsc"]):
        errors.append("IFSC must be 11 characters, e.g. SBIN0003077")
    dob = parse_dob(data.get("dob"))
    if dob is None:
        errors.append("date of birth must be given as DD/MM/YYYY")
    else:
        cleaned["dob"] = dob
        if age_on(dob, now_ist().date()) < MIN_AGE:
            errors.append("applicant must be %d years of age or above" % MIN_AGE)
    if not cleaned["doc_path"]:
        errors.append("age proof document is required")
    if now_ist() > SCHEME_DEADLINE:
        errors.append("the application window has closed")
    return errors, cleaned


def active_application(cur, mobile):
    """The applicant's current live application, if any."""
    cur.execute("SELECT id, application_no, status FROM applications "
                "WHERE mobile = %s AND status IN %s "
                "ORDER BY submitted_at DESC LIMIT 1", (mobile, ACTIVE_STATUSES))
    return cur.fetchone()


def create_application(cur, mobile, cleaned):
    """Insert a validated application; ensure the status-portal account exists.

    The caller commits. Returns (id, application_no).
    """
    app_no = new_application_no()
    cur.execute(
        """INSERT INTO applications
           (application_no, applicant_name, mobile, dob, gender, marital_status,
            husband_name, husband_employer, village, block, bank_account, ifsc,
            doc_path, status, submitted_at)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'PENDING',%s)
           RETURNING id""",
        (app_no, cleaned["applicant_name"], mobile, cleaned["dob"], cleaned["gender"],
         cleaned["marital_status"], cleaned["husband_name"], cleaned["husband_employer"],
         cleaned["village"], cleaned["block"], cleaned["bank_account"], cleaned["ifsc"],
         cleaned["doc_path"], now_ist()))
    new_id = cur.fetchone()[0]

    # status portal account; password is DOB as DDMMYYYY per dept. circular
    portal_pass = cleaned["dob"].strftime("%d%m%Y")
    cur.execute("SELECT count(*) FROM portal_users WHERE mobile = %s", (mobile,))
    if cur.fetchone()[0] == 0:
        cur.execute("INSERT INTO portal_users (mobile, password_hash) VALUES (%s,%s)",
                    (mobile, hash_password(portal_pass)))
    write_audit(cur, new_id, "SUBMIT", "applicant:%s" % mobile)
    return new_id, app_no


# ---------------------------------------------------------------------------
# Public pages
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html", hours_left=deadline_remaining())


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/__gateway/", defaults={"subpath": ""})
@app.route("/__gateway/<path:subpath>")
def gateway_proxy(subpath):
    # Public access to the simulated SMS gateway inbox and message console is disabled
    # so OTP inboxes and SMS message contents are never exposed publicly.
    if not session.get("admin") or not is_gateway_console_enabled():
        return (
            "Forbidden: SMS gateway console and OTP inboxes are not publicly accessible.",
            403,
            {"Content-Type": "text/plain; charset=utf-8"},
        )
    gw_url = (SMS_GATEWAY_URL or "").strip()
    if not gw_url or gw_url.lower() in ("none", "disabled", "off"):
        return ("SMS gateway is disabled.", 404, {"Content-Type": "text/plain; charset=utf-8"})
    try:
        r = requests.get(gw_url.rstrip("/") + "/" + subpath,
                         params=request.args, timeout=5)
        return (r.content, r.status_code,
                {"Content-Type": r.headers.get("Content-Type", "text/html")})
    except Exception:
        return ("SMS gateway unreachable.", 502, {"Content-Type": "text/plain; charset=utf-8"})


# ---------------------------------------------------------------------------
# Application flow: mobile -> OTP -> form steps -> upload -> declaration
# ---------------------------------------------------------------------------

import secrets

_CAPTCHA_TTL_SECONDS = 600


def _ensure_captcha_table():
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS captchas (
                cid         VARCHAR(64) PRIMARY KEY,
                answer      INTEGER,
                used        BOOLEAN DEFAULT FALSE,
                superseded  BOOLEAN DEFAULT FALSE,
                created_at  TIMESTAMP
            )
        """)
        conn.commit()
        cur.close(); conn.close()
    except Exception as e:
        app.logger.error("Error ensuring captchas table: %s" % e)


def _prune_captchas():
    _ensure_captcha_table()
    try:
        cutoff = datetime.now() - timedelta(seconds=_CAPTCHA_TTL_SECONDS)
        conn = get_db()
        cur = conn.cursor()
        cur.execute("DELETE FROM captchas WHERE created_at < %s", (cutoff,))
        conn.commit()
        cur.close(); conn.close()
    except Exception as e:
        app.logger.error("Error pruning captchas: %s" % e)


_orig_save_session = app.session_interface.save_session


def _iframe_aware_save_session(app_obj, sess, response):
    """Ensure SameSite=None; Secure; Partitioned is set on session cookies when
    served over HTTPS or behind the container's external HTTPS reverse proxy
    (where Nginx sets X-Forwarded-Host to the external domain while setting
    X-Forwarded-Proto to its internal http listener scheme), while preserving
    plain HTTP cookies for direct local test suites."""
    _orig_save_session(app_obj, sess, response)
    cookies = response.headers.getlist("Set-Cookie")
    if cookies:
        import re as _re
        proto = request.headers.get("X-Forwarded-Proto", "").split(",")[0].strip().lower()
        fwd_host = request.headers.get("X-Forwarded-Host", "").split(",")[0].strip().lower()
        origin = request.headers.get("Origin", "").strip().lower()
        referer = request.headers.get("Referer", "").strip().lower()
        is_external_proxy = bool(
            fwd_host and not fwd_host.startswith(("localhost", "127.0.0.1"))
        )
        is_https = (
            request.is_secure
            or proto == "https"
            or is_external_proxy
            or origin.startswith("https://")
            or referer.startswith("https://")
        )
        updated = []
        for c in cookies:
            if c.startswith("session=") and is_https:
                c = _re.sub(r";\s*SameSite=[^;]+", "", c, flags=_re.IGNORECASE)
                if "; Secure" not in c:
                    c += "; Secure"
                c += "; SameSite=None; Partitioned"
            updated.append(c)
        response.headers.setlist("Set-Cookie", updated)


app.session_interface.save_session = _iframe_aware_save_session


@app.route("/apply", methods=["GET", "POST"])
def apply():
    if deadline_remaining() is None:
        flash("The application window for this scheme has closed.")
        return redirect(url_for("index"))
    if request.method == "POST":
        mobile = (request.form.get("mobile") or "").strip()
        captcha_raw = (request.form.get("captcha") or "").strip()
        form_cid = (request.form.get("captcha_id") or "").strip()
        captcha_ok = validate_and_consume_captcha(captcha_raw, form_cid)
        if not captcha_ok:
            flash("Security check answer is incorrect. Please try again.")
            q, cid = make_captcha_challenge()
            return render_template("apply.html", captcha_q=q, captcha_id=cid, mobile=mobile)
        if len(mobile) != 10 or not mobile.isdigit():
            flash("Please enter a valid 10-digit mobile number.")
            q, cid = make_captcha_challenge()
            return render_template("apply.html", captcha_q=q, captcha_id=cid, mobile=mobile)
        code = "%06d" % (secrets.randbelow(900000) + 100000)
        conn = get_db()
        cur = conn.cursor()
        cur.execute("INSERT INTO otps (mobile, code, created_at) VALUES (%s, %s, %s)",
                    (mobile, code, now_ist()))
        conn.commit()
        cur.close(); conn.close()
        send_sms(mobile, "Your Sewa Setu OTP is %s. Valid for 5 minutes." % code)
        session.permanent = True
        session["apply_mobile"] = mobile
        session["demo_apply_otp"] = code
        return redirect(url_for("verify"))
    q, cid = make_captcha_challenge()
    return render_template("apply.html", captcha_q=q, captcha_id=cid, mobile="")


def make_captcha_challenge():
    """Generate a new arithmetic challenge stored in shared database across Gunicorn workers."""
    _prune_captchas()
    session.permanent = True
    prev_ans = session.get("captcha_answer")
    prev_cid = session.get("captcha_id")

    conn = get_db()
    cur = conn.cursor()
    if prev_cid:
        if prev_ans is None:
            cur.execute("SELECT answer FROM captchas WHERE cid = %s", (prev_cid,))
            row = cur.fetchone()
            if row:
                prev_ans = row[0]
        cur.execute("UPDATE captchas SET superseded = TRUE WHERE cid = %s", (prev_cid,))
        conn.commit()

    a, b = random.randint(1, 9), random.randint(1, 9)
    while (a + b) == prev_ans:
        a, b = random.randint(1, 9), random.randint(1, 9)

    ans = a + b
    cid = secrets.token_urlsafe(16)
    now_ts = datetime.now()
    cur.execute(
        "INSERT INTO captchas (cid, answer, used, superseded, created_at) VALUES (%s, %s, %s, %s, %s)",
        (cid, ans, False, False, now_ts)
    )
    conn.commit()
    cur.close(); conn.close()

    session["captcha_answer"] = ans
    session["captcha_id"] = cid
    return "%d + %d" % (a, b), cid


def make_captcha():
    q, _ = make_captcha_challenge()
    return q


def validate_and_consume_captcha(raw_captcha, form_cid=""):
    """Validate and immediately consume the active security-check challenge from shared database."""
    _prune_captchas()
    sess_ans = session.pop("captcha_answer", None)
    sess_cid = session.pop("captcha_id", None)

    # Parse integer answer strictly
    if not raw_captcha or not re.fullmatch(r"-?\d+", raw_captcha):
        conn = get_db()
        cur = conn.cursor()
        for c in (sess_cid, form_cid):
            if c:
                cur.execute("UPDATE captchas SET used = TRUE WHERE cid = %s", (c,))
        conn.commit()
        cur.close(); conn.close()
        return False

    try:
        given = int(raw_captcha)
    except (ValueError, TypeError):
        return False

    conn = get_db()
    cur = conn.cursor()

    # If the form included a challenge ID (standard browser form submission)
    if form_cid:
        if sess_cid and form_cid != sess_cid:
            # Stale form submission after session refreshed a newer challenge
            cur.execute("UPDATE captchas SET used = TRUE WHERE cid = %s", (sess_cid,))
            cur.execute("UPDATE captchas SET used = TRUE WHERE cid = %s", (form_cid,))
            conn.commit()
            cur.close(); conn.close()
            return False

        cur.execute("SELECT answer, used, superseded FROM captchas WHERE cid = %s", (form_cid,))
        row = cur.fetchone()
        if not row:
            cur.close(); conn.close()
            return False
        ans, used, superseded = row[0], bool(row[1]), bool(row[2])
        if used or superseded:
            cur.close(); conn.close()
            return False
        cur.execute("UPDATE captchas SET used = TRUE WHERE cid = %s", (form_cid,))
        conn.commit()
        cur.close(); conn.close()
        return given == ans

    # Fallback for automated test clients submitting only session cookies without hidden form_cid
    if sess_cid:
        cur.execute("SELECT answer, used, superseded FROM captchas WHERE cid = %s", (sess_cid,))
        row = cur.fetchone()
        if row:
            ans, used, superseded = row[0], bool(row[1]), bool(row[2])
            if not used and not superseded:
                cur.execute("UPDATE captchas SET used = TRUE WHERE cid = %s", (sess_cid,))
                conn.commit()
                cur.close(); conn.close()
                return given == ans

    cur.close(); conn.close()
    if sess_ans is not None:
        return given == sess_ans

    return False



@app.route("/verify", methods=["GET", "POST"])
def verify():
    sess_mobile = (session.get("apply_mobile") or "").strip()
    if request.method == "GET":
        mobile = sess_mobile
    else:
        mobile = sess_mobile or (request.form.get("mobile") or "").strip()
    if not mobile or len(mobile) != 10 or not mobile.isdigit():
        return redirect(url_for("apply"))

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT code, created_at FROM otps WHERE mobile = %s ORDER BY id DESC LIMIT 1",
        (mobile,),
    )
    row = cur.fetchone()
    cur.close()
    conn.close()

    # Only display the simulated OTP to the browser session that initiated the OTP request,
    # never querying or exposing OTPs for arbitrary mobile numbers from the database.
    sim_otp = ""
    if is_demo_otp_enabled() and sess_mobile and sess_mobile == mobile:
        sim_otp = session.get("demo_apply_otp") or ""

    if request.method == "POST":
        code = request.form.get("otp", "").strip()
        if row and secrets.compare_digest(row[0], code):
            age = (datetime.now() - row[1]).total_seconds()
            if age > OTP_VALIDITY_SECONDS:
                session.pop("demo_apply_otp", None)
                app.logger.warning("otp expired mobile=%s age=%ds" % (mobile, int(age)))
                flash("OTP expired. Please request a new OTP.")
                return redirect(url_for("apply"))
            session.pop("demo_apply_otp", None)
            session["verified_mobile"] = mobile
            return redirect(url_for("form_step", step=1))
        flash("Invalid OTP.")
    return render_template("verify.html", mobile=mobile, sim_otp=sim_otp)


@app.route("/form/<int:step>", methods=["GET", "POST"])
def form_step(step):
    if not session.get("verified_mobile"):
        flash("Session expired. Please verify your mobile number again.")
        return redirect(url_for("apply"))
    if step not in (1, 2, 3):
        abort(404)
    if request.method == "POST":
        data = dict(session.get("form_data", {}))
        if step == 2:
            raw_block = request.form.get("block", "")
            raw_village = request.form.get("village", "")
            raw_village_other = request.form.get("village_other", "")
            strict_dropdown = request.form.get("location_dropdown_mode") == "1"
            loc_errors, c_block, c_village = resolve_and_validate_location(
                raw_block,
                raw_village,
                raw_village_other,
                require_mapped_unless_other=strict_dropdown,
            )
            data["block"] = c_block
            data["village"] = c_village
            session["form_data"] = data
            if loc_errors:
                for err in loc_errors:
                    flash("Invalid address details: " + err + ".")
                return render_template(
                    "form_step2.html",
                    data=data,
                    blocks=BLOCKS,
                    block_villages=BLOCK_VILLAGES,
                )
        else:
            for k, v in request.form.items():
                data[k] = v
            session["form_data"] = data
        if step < 3:
            return redirect(url_for("form_step", step=step + 1))
        return redirect(url_for("upload"))
    form_data = dict(session.get("form_data", {}))
    if step == 2 and request.args.get("block") in BLOCKS and not form_data.get("block"):
        form_data["block"] = request.args.get("block")
    return render_template("form_step%d.html" % step,
                           data=form_data, blocks=BLOCKS,
                           block_villages=BLOCK_VILLAGES)


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if not session.get("verified_mobile"):
        flash("Session expired. Please verify your mobile number again.")
        return redirect(url_for("apply"))
    if request.method == "POST":
        f = request.files.get("document")
        if f is None or f.filename == "":
            flash("Please choose a file to upload (JPG, PNG or PDF, up to 5 MB).")
            return render_template("upload.html")
        filename = f.filename.lower()
        content = f.read()
        if not filename.rsplit(".", 1)[-1] in ("pdf", "jpg", "jpeg", "png"):
            flash("Please upload a JPG, PNG or PDF file.")
            return render_template("upload.html")
        if len(content) > 5 * 1024 * 1024:
            flash("File is larger than 5 MB. Please upload a smaller file.")
            return render_template("upload.html")
        os.makedirs(UPLOAD_DIR, exist_ok=True)
        import time as _time
        path = os.path.join(UPLOAD_DIR, "%s_%d_%s" % (session["verified_mobile"], int(_time.time()), filename))
        with open(path, "wb") as out:
            out.write(content)
        session["doc_path"] = path
        return redirect(url_for("declaration"))
    return render_template("upload.html")


@app.route("/declaration", methods=["GET", "POST"])
def declaration():
    if not session.get("verified_mobile"):
        flash("Session expired. Please verify your mobile number again.")
        return redirect(url_for("apply"))
    if request.method == "POST":
        return handle_submission()
    # Preview everything before the applicant commits.
    data = session.get("form_data", {})
    errors, _ = validate_application(data, session.get("doc_path", ""))
    return render_template("declaration.html", data=data, errors=errors,
                           doc_name=os.path.basename(session.get("doc_path", "") or ""))


def handle_submission():
    mobile = session.get("verified_mobile")
    data = session.get("form_data", {})
    errors, cleaned = validate_application(data, session.get("doc_path", ""))
    if errors:
        flash("Please correct the following before submitting: " + "; ".join(errors) + ".")
        return redirect(url_for("form_step", step=1))

    conn = get_db()
    cur = conn.cursor()
    existing = active_application(cur, mobile)
    if existing:
        cur.close(); conn.close()
        flash("Application %s (%s) already exists for this mobile number. A pending "
              "application can be withdrawn from the status portal if you need to "
              "apply afresh." % (existing[1], existing[2]))
        return redirect(url_for("index"))

    new_id, app_no = create_application(cur, mobile, cleaned)
    conn.commit()
    cur.close(); conn.close()

    session.pop("form_data", None)
    session.pop("doc_path", None)
    session.pop("verified_mobile", None)
    # The applicant just proved ownership of this mobile by OTP, so let them
    # see their application and download the acknowledgment without a second login.
    session["logged_in"] = True
    session["portal_mobile"] = mobile
    send_sms(mobile, "Sewa Setu: application %s received. Track at the status portal "
                     "with your registered mobile number and OTP." % app_no)
    return render_template("confirmation.html", app_no=app_no, app_id=new_id)


def generate_acknowledgment(cur, app_id):
    cur.execute("SELECT application_no, applicant_name, mobile, dob, village, block, "
                "bank_account, ifsc, submitted_at, status FROM applications WHERE id = %s",
                (app_id,))
    row = cur.fetchone()
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, "GOVERNMENT OF PURVANCHAL", ln=1, align="C")
    pdf.set_font("Helvetica", "", 11)
    pdf.cell(0, 8, "Department of Social Welfare", ln=1, align="C")
    pdf.cell(0, 8, "Old Age Pension Scheme - Acknowledgment", ln=1, align="C")
    pdf.ln(4)
    # letterhead rules
    pdf.line(10, 12, 200, 12)
    pdf.line(10, 282, 200, 282)
    labels = ["Application No", "Applicant Name", "Mobile", "Date of Birth",
              "Village", "Block", "Bank Account", "IFSC", "Submitted At", "Status"]
    pdf.set_font("Helvetica", "", 10)
    for label, val in zip(labels, row):
        try:
            pdf.cell(60, 8, label, border=1)
            pdf.cell(0, 8, str(val), border=1, ln=1)
        except Exception:
            pdf.cell(0, 8, "?", border=1, ln=1)
    pdf.ln(6)
    pdf.set_font("Helvetica", "I", 9)
    pdf.multi_cell(0, 5, "This is a computer generated acknowledgment. Processing SLA "
                         "as per the Purvanchal Right to Public Services Act applies.")
    return bytes(pdf.output())


# ---------------------------------------------------------------------------
# Status portal (OTP-based citizen tracking)
# ---------------------------------------------------------------------------

@app.route("/status", methods=["GET", "POST"])
def status_login():
    if request.method == "POST":
        mobile = (request.form.get("mobile") or "").strip()
        if not mobile or len(mobile) != 10 or not mobile.isdigit():
            flash("Please enter a valid 10-digit mobile number.")
            return render_template("status_login.html")
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM applications WHERE mobile = %s LIMIT 1", (mobile,))
        exists = cur.fetchone()
        if not exists:
            cur.close(); conn.close()
            flash("Mobile number not registered. Please apply first.")
            return render_template("status_login.html")

        # Generate 6-digit OTP
        code = "%06d" % (secrets.randbelow(900000) + 100000)
        cur.execute("INSERT INTO otps (mobile, code, created_at) VALUES (%s, %s, %s)",
                    (mobile, code, now_ist()))
        conn.commit()
        cur.close(); conn.close()

        send_sms(mobile, "Sewa Setu: your OTP for application status tracking is %s." % code)
        session["status_mobile"] = mobile
        session["demo_status_otp"] = code
        return redirect(url_for("status_verify"))
    return render_template("status_login.html")


@app.route("/status/verify", methods=["GET", "POST"])
def status_verify():
    sess_mobile = (session.get("status_mobile") or "").strip()
    if request.method == "GET":
        mobile = sess_mobile
    else:
        mobile = sess_mobile or (request.form.get("mobile") or "").strip()
    if not mobile or len(mobile) != 10 or not mobile.isdigit():
        flash("Please enter your registered mobile number to receive an OTP.")
        return redirect(url_for("status_login"))

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT code, created_at FROM otps WHERE mobile = %s ORDER BY id DESC LIMIT 1",
        (mobile,),
    )
    row = cur.fetchone()
    cur.close(); conn.close()

    # Only display the simulated OTP to the browser session that initiated the status OTP request.
    sim_otp = ""
    if is_demo_otp_enabled() and sess_mobile and sess_mobile == mobile:
        sim_otp = session.get("demo_status_otp") or ""

    if request.method == "POST":
        code = request.form.get("otp", "").strip()
        if row and secrets.compare_digest(row[0], code):
            age = (datetime.now() - row[1]).total_seconds()
            if age > OTP_VALIDITY_SECONDS:
                session.pop("demo_status_otp", None)
                app.logger.warning("status otp expired mobile=%s age=%ds" % (mobile, int(age)))
                flash("OTP expired. Please request a new OTP.")
                return redirect(url_for("status_login"))
            session["logged_in"] = True
            session["portal_mobile"] = mobile
            session.pop("status_mobile", None)
            session.pop("demo_status_otp", None)
            conn = get_db()
            cur = conn.cursor()
            cur.execute(
                "SELECT id FROM applications WHERE mobile = %s ORDER BY submitted_at DESC LIMIT 1",
                (mobile,),
            )
            r = cur.fetchone()
            cur.close(); conn.close()
            if r:
                return redirect(url_for("view_application", app_id=r[0]))
            flash("No application found for this mobile number.")
            return redirect(url_for("status_login"))
        flash("Invalid OTP.")
    return render_template("status_verify.html", mobile=mobile, sim_otp=sim_otp)


@app.route("/application/<int:app_id>")
def view_application(app_id):
    if not session.get("logged_in"):
        flash("Please login to view application status.")
        return redirect(url_for("status_login"))
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT application_no, applicant_name, mobile, dob, village, block, "
                "bank_account, ifsc, status, submitted_at, decided_at "
                "FROM applications WHERE id = %s AND mobile = %s",
                (app_id, session.get("portal_mobile")))
    row = cur.fetchone()
    cur.close(); conn.close()
    if not row:
        abort(404)
    return render_template("application.html", a=row, app_id=app_id)


@app.route("/application/<int:app_id>/withdraw", methods=["POST"])
def withdraw_application(app_id):
    """Applicant withdraws their own PENDING application so they can apply afresh."""
    if not session.get("logged_in") or not session.get("portal_mobile"):
        flash("Please login to manage your application.")
        return redirect(url_for("status_login"))
    mobile = session["portal_mobile"]
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE applications SET status = 'WITHDRAWN', decided_at = %s, "
                "decided_by = 'APPLICANT' WHERE id = %s AND mobile = %s "
                "AND status = 'PENDING' RETURNING application_no",
                (now_ist(), app_id, mobile))
    row = cur.fetchone()
    if row:
        write_audit(cur, app_id, "WITHDRAW", "applicant:%s" % mobile)
        conn.commit()
        flash("Application %s has been withdrawn. You may submit a new application." % row[0])
    else:
        flash("Only a pending application can be withdrawn.")
    cur.close(); conn.close()
    return redirect(url_for("view_application", app_id=app_id))


@app.route("/ack/<int:app_id>.pdf")
def ack_pdf(app_id):
    if not session.get("admin"):
        conn0 = get_db(); c0 = conn0.cursor()
        c0.execute("SELECT 1 FROM applications WHERE id = %s AND mobile = %s",
                   (app_id, session.get("portal_mobile")))
        owned = c0.fetchone()
        c0.close(); conn0.close()
        if not owned:
            abort(403)
    path = os.path.join(UPLOAD_DIR, "ack", "%d.pdf" % app_id)
    if not os.path.exists(path):
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT id FROM applications WHERE id = %s", (app_id,))
        if not cur.fetchone():
            cur.close(); conn.close()
            abort(404)
        try:
            data = generate_acknowledgment(cur, app_id)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as _pdf_f:
                _pdf_f.write(data)
        except Exception as e:
            app.logger.error("Failed to generate acknowledgment PDF for app %s: %s", app_id, e)
            cur.close(); conn.close()
            return ("Failed to generate acknowledgment PDF.", 500, {"Content-Type": "text/plain; charset=utf-8"})
        cur.close(); conn.close()
        resp = send_file(
            io.BytesIO(data),
            mimetype="application/pdf",
            as_attachment=True,
            download_name="SewaSetu_Ack_%d.pdf" % app_id,
        )
        resp.headers["Content-Type"] = "application/pdf"
        resp.headers["Content-Disposition"] = 'attachment; filename="SewaSetu_Ack_%d.pdf"' % app_id
        return resp
    resp = send_file(
        path,
        mimetype="application/pdf",
        as_attachment=True,
        download_name="SewaSetu_Ack_%d.pdf" % app_id,
    )
    resp.headers["Content-Type"] = "application/pdf"
    resp.headers["Content-Disposition"] = 'attachment; filename="SewaSetu_Ack_%d.pdf"' % app_id
    return resp


@app.route("/status/reset", methods=["GET", "POST"])
def reset_password():
    flash("Citizen status tracking is now OTP-based. No password is required.")
    return redirect(url_for("status_login"))


# ---------------------------------------------------------------------------
# Admin
# ---------------------------------------------------------------------------

@app.route("/admin", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        if (ADMIN_PASSWORD and secrets.compare_digest(request.form.get("username", ""), ADMIN_USERNAME) and
                secrets.compare_digest(request.form.get("password", ""), ADMIN_PASSWORD)):
            session["logged_in"] = True
            session["admin"] = True
            session["admin_user"] = ADMIN_USERNAME
            return redirect(url_for("admin_dashboard"))
        flash("Invalid credentials.")
    return render_template("admin_login.html")


@app.route("/admin/dashboard")
def admin_dashboard():
    if not session.get("admin"):
        return redirect(url_for("admin_login"))
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT status, count(*) FROM applications GROUP BY status")
    by_status = cur.fetchall()
    cur.execute("SELECT count(*) FROM applications WHERE status = 'PENDING' "
                "AND submitted_at < %s", (now_ist() - timedelta(days=SLA_DAYS),))
    overdue = cur.fetchone()[0]
    cur.execute("SELECT block, count(*) FROM applications WHERE status = 'PENDING' "
                "GROUP BY block ORDER BY count(*) DESC")
    by_block = cur.fetchall()
    cur.close(); conn.close()
    return render_template("admin_dashboard.html", by_status=by_status,
                           overdue=overdue, by_block=by_block, sla=SLA_DAYS)


@app.route("/admin/applications")
def admin_list():
    if not session.get("admin"):
        return redirect(url_for("admin_login"))
    status = request.args.get("status", "PENDING")
    mobile = request.args.get("mobile", "").strip()
    page = int(request.args.get("page", 1))
    conn = get_db()
    cur = conn.cursor()
    if mobile:
        cur.execute("SELECT id, application_no, applicant_name, mobile, block, status, "
                    "submitted_at FROM applications WHERE mobile = %s ORDER BY submitted_at ASC LIMIT 200",
                    (mobile,))
        status = "mobile %s" % mobile
    else:
        cur.execute("SELECT id, application_no, applicant_name, mobile, block, status, "
                    "submitted_at FROM applications WHERE status = %s "
                    "ORDER BY submitted_at ASC LIMIT 50 OFFSET %s",
                    (status, (page - 1) * 50))
    rows = cur.fetchall()
    cur.close(); conn.close()
    return render_template("admin_list.html", rows=rows, status=status, page=page, mobile=mobile)


@app.route("/admin/application/<int:app_id>")
def admin_view(app_id):
    if not session.get("admin"):
        return redirect(url_for("admin_login"))
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT application_no, applicant_name, mobile, dob, gender, "
                "marital_status, village, block, bank_account, ifsc, doc_path, "
                "status, submitted_at, decided_at, decided_by "
                "FROM applications WHERE id = %s", (app_id,))
    row = cur.fetchone()
    if not row:
        cur.close(); conn.close()
        abort(404)
    cur.execute("SELECT at, action, actor, note FROM audit_log "
                "WHERE application_id = %s ORDER BY at ASC", (app_id,))
    audit = cur.fetchall()
    cur.close(); conn.close()
    return render_template("admin_view.html", a=row, app_id=app_id, audit=audit)


def _admin_decide(app_id, new_status, note):
    """Approve/reject a PENDING application, recording who decided and when."""
    if not session.get("admin"):
        abort(403)
    actor = session.get("admin_user", ADMIN_USERNAME)
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE applications SET status = %s, decided_at = %s, decided_by = %s "
                "WHERE id = %s AND status = 'PENDING' RETURNING application_no, mobile",
                (new_status, now_ist(), actor, app_id))
    row = cur.fetchone()
    if row:
        write_audit(cur, app_id, new_status, "admin:%s" % actor, note)
        conn.commit()
        flash("Application %s %s." % (row[0], new_status.lower()))
        # Notify the citizen by SMS (mirrors the MCP officer tool behaviour).
        sms_text = (
            "Sewa Setu: your pension application %s has been APPROVED by the block office." % row[0]
            if new_status == "APPROVED"
            else "Sewa Setu: your pension application %s was not approved. Reason: %s." % (row[0], note or "see portal")
        )
        send_sms(row[1], sms_text)
    else:
        flash("Only a pending application can be decided.")
    cur.close(); conn.close()
    return redirect(url_for("admin_view", app_id=app_id))


@app.route("/admin/approve/<int:app_id>", methods=["POST"])
def admin_approve(app_id):
    return _admin_decide(app_id, "APPROVED", request.form.get("note", ""))


@app.route("/admin/reject/<int:app_id>", methods=["POST"])
def admin_reject(app_id):
    return _admin_decide(app_id, "REJECTED", request.form.get("note", ""))


import oauth
app.register_blueprint(oauth.oauth)
csrf.exempt(oauth.oauth)  # OAuth 2.1 endpoints are API-only; CSRF does not apply

import mcp_server
app.register_blueprint(mcp_server.mcp_bp)
csrf.exempt(mcp_server.mcp_bp)  # MCP is a JSON-RPC API; CSRF does not apply

# ---------------------------------------------------------------------------
# Evaluation Dashboard (/eval-dashboard)
# ---------------------------------------------------------------------------

_LATEST_EVAL_RESULTS = None

@app.route("/eval-dashboard", methods=["GET"])
def eval_dashboard():
    if not session.get("admin"):
        flash("Please log in as an administrator to access the evaluation dashboard.")
        return redirect(url_for("admin_login"))
    global _LATEST_EVAL_RESULTS
    if _LATEST_EVAL_RESULTS is None:
        try:
            import eval_engine
            _LATEST_EVAL_RESULTS = eval_engine.run_all_evaluations()
        except Exception as e:
            app.logger.error("Error running initial evaluations: %s" % e)
            _LATEST_EVAL_RESULTS = {
                "timestamp": now_ist().strftime("%Y-%m-%d %H:%M:%S IST"),
                "total": 0, "passed": 0, "failed": 0, "pass_rate": 0, "scenarios": []
            }
    import oauth
    return render_template("eval_dashboard.html", summary=_LATEST_EVAL_RESULTS, issuer=oauth.get_external_issuer())


@app.route("/eval-dashboard/run", methods=["POST"])
def eval_dashboard_run():
    if not session.get("admin"):
        abort(403)
    global _LATEST_EVAL_RESULTS
    try:
        import eval_engine
        _LATEST_EVAL_RESULTS = eval_engine.run_all_evaluations()
        flash("Evaluations completed successfully: %d of %d passed (%s%%)."
              % (_LATEST_EVAL_RESULTS["passed"], _LATEST_EVAL_RESULTS["total"], _LATEST_EVAL_RESULTS["pass_rate"]))
    except Exception as e:
        flash("Error executing evaluations: %s" % e)
    return redirect(url_for("eval_dashboard"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 3000)), debug=False)

