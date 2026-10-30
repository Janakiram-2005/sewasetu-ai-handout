# -*- coding: utf-8 -*-
"""
Database compatibility layer for Sewa Setu.

Attempts a real PostgreSQL connection via psycopg2 first (matching config/app.ini
or DATABASE_URL). When the external Docker PostgreSQL host (`db:5432`) is not
reachable in a single-container runtime, transparently falls back to a local
SQLite database initialized from `/app/schema.sql` with a psycopg2-compatible
connection and cursor interface.
"""

import hashlib
import json
import os
import re
import sqlite3
import threading
from datetime import date, datetime, timedelta

try:
    import psycopg2
except ImportError:
    psycopg2 = None

_INIT_LOCK = threading.Lock()
_SQLITE_INITIALIZED = False

_TIMESTAMP_COLS = {
    "submitted_at",
    "decided_at",
    "created_at",
    "fetched_at",
    "expires_at",
    "revoked_at",
    "at",
}
_DATE_COLS = {"dob"}
_JSON_COLS = {"redirect_uris", "params"}


def _parse_dt(val):
    if val is None or isinstance(val, datetime):
        return val
    if isinstance(val, bytes):
        val = val.decode("utf-8")
    if isinstance(val, str):
        val = val.strip()
        for fmt in (
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
        ):
            try:
                return datetime.strptime(val, fmt)
            except ValueError:
                continue
    return val


def _parse_date(val):
    if val is None or isinstance(val, date) and not isinstance(val, datetime):
        return val
    if isinstance(val, datetime):
        return val.date()
    if isinstance(val, bytes):
        val = val.decode("utf-8")
    if isinstance(val, str):
        val = val.strip()
        for fmt in ("%Y-%m-%d", "%d/%m/%Y"):
            try:
                return datetime.strptime(val[:10], fmt).date()
            except ValueError:
                continue
    return val


def _adapt_param(val):
    if isinstance(val, datetime):
        return val.strftime("%Y-%m-%d %H:%M:%S.%f")
    if isinstance(val, date):
        return val.strftime("%Y-%m-%d")
    return val


class _CompatCursor:
    def __init__(self, raw_cursor):
        self._cur = raw_cursor

    @property
    def rowcount(self):
        return self._cur.rowcount

    @property
    def description(self):
        return self._cur.description

    def execute(self, sql, params=None):
        if params is not None:
            flat_params = []
            parts = sql.split("%s")
            if len(parts) - 1 != len(params):
                # Fallback if %s count doesn't match
                translated_sql = sql.replace("%s", "?")
                flat_params = [_adapt_param(p) for p in params]
            else:
                out_sql = [parts[0]]
                for idx, p in enumerate(params):
                    if isinstance(p, (tuple, list)):
                        placeholders = ", ".join("?" for _ in p)
                        out_sql.append("(" + placeholders + ")")
                        for item in p:
                            flat_params.append(_adapt_param(item))
                    else:
                        out_sql.append("?")
                        flat_params.append(_adapt_param(p))
                    out_sql.append(parts[idx + 1])
                translated_sql = "".join(out_sql)
            self._cur.execute(translated_sql, flat_params)
        else:
            self._cur.execute(sql)

    def _convert_row(self, row):
        if row is None:
            return None
        desc = self._cur.description
        if not desc:
            return row
        out = []
        for idx, val in enumerate(row):
            col_name = desc[idx][0].lower() if idx < len(desc) and desc[idx][0] else ""
            if col_name in _TIMESTAMP_COLS:
                val = _parse_dt(val)
            elif col_name in _DATE_COLS:
                val = _parse_date(val)
            elif col_name in _JSON_COLS and isinstance(val, (str, bytes)):
                try:
                    val = json.loads(val.decode("utf-8") if isinstance(val, bytes) else val)
                except Exception:
                    pass
            out.append(val)
        return tuple(out)

    def fetchone(self):
        return self._convert_row(self._cur.fetchone())

    def fetchall(self):
        rows = self._cur.fetchall()
        return [self._convert_row(r) for r in rows]

    def close(self):
        self._cur.close()


class _CompatConnection:
    def __init__(self, raw_conn):
        self._conn = raw_conn

    def cursor(self):
        return _CompatCursor(self._conn.cursor())

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()


def _sqlite_db_path():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.environ.get("SEWASETU_DATA_DIR") or os.path.join(os.path.dirname(base_dir), ".data")
    try:
        os.makedirs(data_dir, exist_ok=True)
    except Exception:
        data_dir = "/tmp/sewasetu_data"
        os.makedirs(data_dir, exist_ok=True)
    return os.path.join(data_dir, "sewasetu.db")


def _init_sqlite_schema_and_seed(raw_conn):
    global _SQLITE_INITIALIZED
    if _SQLITE_INITIALIZED:
        return
    with _INIT_LOCK:
        if _SQLITE_INITIALIZED:
            return
        base_dir = os.path.dirname(os.path.abspath(__file__))
        schema_path = os.path.join(base_dir, "schema.sql")
        with open(schema_path, "r", encoding="utf-8") as fh:
            schema_sql = fh.read()
        # Convert PostgreSQL SERIAL PRIMARY KEY and JSONB to SQLite equivalents
        sqlite_schema = re.sub(
            r"\bSERIAL\s+PRIMARY\s+KEY\b",
            "INTEGER PRIMARY KEY AUTOINCREMENT",
            schema_sql,
            flags=re.IGNORECASE,
        )
        sqlite_schema = re.sub(r"\bJSONB\b", "TEXT", sqlite_schema, flags=re.IGNORECASE)
        raw_conn.executescript(sqlite_schema)

        cur = raw_conn.cursor()
        cur.execute("SELECT count(*) FROM applications")
        count = cur.fetchone()[0]
        if count == 0:
            now = datetime.now()
            sample_apps = [
                (
                    "SSP26100101",
                    "Kamala Devi",
                    "9864011201",
                    date(1958, 3, 14),
                    "Female",
                    "Widowed",
                    "Late Bhupen Bora",
                    "",
                    "Disangmukh",
                    "Sonari",
                    "30918273645",
                    "SBIN0003077",
                    "/var/sewasetu/uploads/9864011201_voter_id.pdf",
                    "PENDING",
                    now - timedelta(days=4, hours=3),
                    None,
                    None,
                ),
                (
                    "SSP26100102",
                    "Haren Gogoi",
                    "9864011202",
                    date(1955, 8, 22),
                    "Male",
                    "Married",
                    "",
                    "",
                    "Boko Bazar",
                    "Rajapara",
                    "31827364556",
                    "SBIN0004120",
                    "/var/sewasetu/uploads/9864011202_birth_cert.pdf",
                    "PENDING",
                    now - timedelta(days=18, hours=6),
                    None,
                    None,
                ),
                (
                    "SSP26100103",
                    "Bina Kalita",
                    "9864011203",
                    date(1960, 1, 10),
                    "Female",
                    "Married",
                    "",
                    "",
                    "Silapathar",
                    "Dhemaji Pathar",
                    "32736455467",
                    "PUNB0041200",
                    "/var/sewasetu/uploads/9864011203_age_proof.jpg",
                    "APPROVED",
                    now - timedelta(days=12, hours=2),
                    now - timedelta(days=5, hours=1),
                    "admin",
                ),
                (
                    "SSP26100104",
                    "Pradip Baruah",
                    "9864011204",
                    date(1952, 11, 5),
                    "Male",
                    "Widowed",
                    "",
                    "",
                    "Barpeta Road",
                    "Borgaon",
                    "33645546378",
                    "UCBA0001023",
                    "/var/sewasetu/uploads/9864011204_voter_card.pdf",
                    "DEEMED_APPROVED",
                    now - timedelta(days=25, hours=4),
                    now - timedelta(days=9, hours=22),
                    "RTPS-AUTO",
                ),
                (
                    "SSP26100105",
                    "Renu Saikia",
                    "9864011205",
                    date(1962, 6, 30),
                    "Female",
                    "Unmarried",
                    "",
                    "",
                    "Amguri",
                    "Namti",
                    "34554637289",
                    "SBIN0003077",
                    "/var/sewasetu/uploads/9864011205_school_cert.pdf",
                    "PENDING",
                    now - timedelta(days=2, hours=5),
                    None,
                    None,
                ),
                (
                    "SSP26100106",
                    "Mahendra Nath",
                    "9864011206",
                    date(1959, 4, 19),
                    "Male",
                    "Married",
                    "",
                    "",
                    "Sivasagar Chariali",
                    "Khelua",
                    "35463728190",
                    "SBIN0000182",
                    "/var/sewasetu/uploads/9864011206_voter_id.pdf",
                    "REJECTED",
                    now - timedelta(days=10, hours=1),
                    now - timedelta(days=6, hours=4),
                    "admin",
                ),
            ]
            for row in sample_apps:
                cur.execute(
                    """INSERT INTO applications
                       (application_no, applicant_name, mobile, dob, gender, marital_status,
                        husband_name, husband_employer, village, block, bank_account, ifsc,
                        doc_path, status, submitted_at, decided_at, decided_by)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        row[0],
                        row[1],
                        row[2],
                        _adapt_param(row[3]),
                        row[4],
                        row[5],
                        row[6],
                        row[7],
                        row[8],
                        row[9],
                        row[10],
                        row[11],
                        row[12],
                        row[13],
                        _adapt_param(row[14]),
                        _adapt_param(row[15]),
                        row[16],
                    ),
                )
                app_id = cur.lastrowid
                dob_pass = row[3].strftime("%d%m%Y")
                pw_hash = hashlib.sha256(dob_pass.encode("utf-8")).hexdigest()
                cur.execute(
                    "INSERT OR IGNORE INTO portal_users (mobile, password_hash) VALUES (?, ?)",
                    (row[2], pw_hash),
                )
                cur.execute(
                    "INSERT INTO audit_log (application_id, action, actor, note, at) VALUES (?, ?, ?, ?, ?)",
                    (app_id, "SUBMIT", "applicant:%s" % row[2], "", _adapt_param(row[14])),
                )
                if row[13] in ("APPROVED", "REJECTED", "DEEMED_APPROVED") and row[15]:
                    actor = "system:rtps-cron" if row[13] == "DEEMED_APPROVED" else ("admin:%s" % row[16])
                    note = "not processed within SLA" if row[13] == "DEEMED_APPROVED" else "Verified by block office"
                    cur.execute(
                        "INSERT INTO audit_log (application_id, action, actor, note, at) VALUES (?, ?, ?, ?, ?)",
                        (app_id, row[13], actor, note, _adapt_param(row[15])),
                    )
            raw_conn.commit()
        cur.close()
        _SQLITE_INITIALIZED = True


_PG_SCHEMA_INITIALIZED = False


def is_production_env():
    """Return True when running on Render or with production environment flags."""
    return bool(
        os.environ.get("RENDER")
        or os.environ.get("APP_ENV", "").strip().lower() == "production"
        or os.environ.get("FLASK_ENV", "").strip().lower() == "production"
        or os.environ.get("REQUIRE_POSTGRES", "").strip() == "1"
    )


def normalize_database_url(db_url):
    """Normalize postgres:// URI scheme to postgresql:// for psycopg2 compatibility."""
    url = (db_url or "").strip()
    if url.startswith("postgres://"):
        return "postgresql://" + url[len("postgres://"):]
    return url


def _init_postgres_schema(pg_conn):
    """Safely initialize non-destructive CREATE TABLE/INDEX IF NOT EXISTS statements on PostgreSQL."""
    global _PG_SCHEMA_INITIALIZED
    if _PG_SCHEMA_INITIALIZED:
        return
    with _INIT_LOCK:
        if _PG_SCHEMA_INITIALIZED:
            return
        base_dir = os.path.dirname(os.path.abspath(__file__))
        schema_path = os.path.join(base_dir, "schema.sql")
        with open(schema_path, "r", encoding="utf-8") as fh:
            schema_sql = fh.read()
        if re.search(r"\b(DROP|TRUNCATE|DELETE)\b", schema_sql, flags=re.IGNORECASE):
            raise RuntimeError("Refusing to execute schema.sql containing destructive SQL statements.")
        cur = pg_conn.cursor()
        try:
            cur.execute(schema_sql)
            pg_conn.commit()
            _PG_SCHEMA_INITIALIZED = True
        except Exception:
            pg_conn.rollback()
            raise
        finally:
            cur.close()


def connect_db(config):
    """Connect to PostgreSQL via DATABASE_URL (failing clearly if unavailable in production),
    or fall back to local SQLite only in non-production local development."""
    raw_db_url = (os.environ.get("DATABASE_URL") or "").strip()
    db_url = normalize_database_url(raw_db_url)
    env_db_host = (os.environ.get("DB_HOST") or "").strip()
    cfg_db_host = config.get("database", "host") if config and config.has_option("database", "host") else ""
    prod_mode = is_production_env()

    # 1. Explicit DATABASE_URL or production mode: require PostgreSQL, never fall back to SQLite
    if db_url or prod_mode or env_db_host:
        if psycopg2 is None:
            raise RuntimeError("Production PostgreSQL driver (psycopg2) is not installed.")
        if not db_url and not env_db_host:
            raise RuntimeError(
                "DATABASE_URL is required in production mode. Refusing to fall back to temporary SQLite."
            )
        try:
            if db_url:
                pg_conn = psycopg2.connect(db_url, connect_timeout=5)
            else:
                pg_conn = psycopg2.connect(
                    host=env_db_host,
                    port=os.environ.get("DB_PORT") or config.get("database", "port"),
                    dbname=os.environ.get("DB_NAME") or config.get("database", "name"),
                    user=os.environ.get("DB_USER") or config.get("database", "user"),
                    password=os.environ.get("DB_PASSWORD") or config.get("database", "password"),
                    connect_timeout=5,
                )
            _init_postgres_schema(pg_conn)
            return pg_conn
        except Exception as exc:
            raise RuntimeError(f"PostgreSQL database connection failed: {exc}") from exc

    # 2. Local Docker Compose fallback when db:5432 is reachable in non-production mode
    if psycopg2 is not None and cfg_db_host and cfg_db_host != "db":
        try:
            pg_conn = psycopg2.connect(
                host=cfg_db_host,
                port=config.get("database", "port"),
                dbname=config.get("database", "name"),
                user=config.get("database", "user"),
                password=config.get("database", "password"),
                connect_timeout=2,
            )
            _init_postgres_schema(pg_conn)
            return pg_conn
        except Exception:
            pass

    # 3. Single-container local development/preview fallback (non-production only)
    db_path = _sqlite_db_path()
    raw_conn = sqlite3.connect(db_path, timeout=30.0, check_same_thread=False)
    _init_sqlite_schema_and_seed(raw_conn)
    return _CompatConnection(raw_conn)

