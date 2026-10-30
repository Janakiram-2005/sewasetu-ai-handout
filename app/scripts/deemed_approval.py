# -*- coding: utf-8 -*-
"""
Nightly deemed-approval job.

Under the Purvanchal Right to Public Services Act, an application not processed
within the statutory SLA stands approved. This job marks such applications
DEEMED_APPROVED and notifies the applicant by SMS.

Scheduled via cron, 02:00 daily. See deploy/crontab.
"""

import os
import sys
import time
import configparser
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT_DIR = os.path.dirname(BASE_DIR)
PYLIBS_DIR = os.path.join(ROOT_DIR, ".pylibs")

if os.path.isdir(PYLIBS_DIR) and PYLIBS_DIR not in sys.path:
    sys.path.insert(0, PYLIBS_DIR)
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import requests
from db_compat import connect_db, is_production_env

IST = ZoneInfo("Asia/Kolkata")


def now_ist():
    """Return current Indian Standard Time (naive) matching portal clock."""
    return datetime.now(IST).replace(tzinfo=None)


config = configparser.ConfigParser()
CONFIG_PATH = os.path.join(BASE_DIR, "config", "app.ini")
with open(CONFIG_PATH) as fh:
    config.read_file(fh)

SLA_DAYS = config.getint("pension", "sla_days")
SMS_GATEWAY_URL = (
    os.environ.get("SMS_GATEWAY_URL")
    if "SMS_GATEWAY_URL" in os.environ
    else ("" if is_production_env() else config.get("app", "sms_gateway_url", fallback=""))
)


def main(reference_time=None):
    """
    Mark PENDING applications submitted more than SLA_DAYS before `reference_time`
    as DEEMED_APPROVED. Only transitions applications currently in PENDING status,
    never overwriting prior officer APPROVED/REJECTED decisions.
    """
    current_dt = reference_time if reference_time is not None else now_ist()
    cutoff = current_dt - timedelta(days=SLA_DAYS)

    conn = connect_db(config)
    cur = conn.cursor()
    cur.execute(
        """UPDATE applications
           SET status = 'DEEMED_APPROVED', decided_at = %s, decided_by = 'RTPS-AUTO'
           WHERE status = 'PENDING' AND submitted_at <= %s
           RETURNING id, application_no, mobile""",
        (current_dt, cutoff),
    )
    rows = cur.fetchall()
    for app_id, app_no, mobile in rows:
        cur.execute(
            "INSERT INTO audit_log (application_id, action, actor, note, at) "
            "VALUES (%s, 'DEEMED_APPROVED', 'system:rtps-cron', "
            "'not processed within SLA', %s)",
            (app_id, current_dt),
        )
    conn.commit()
    gw_url = (SMS_GATEWAY_URL or "").strip()
    if gw_url and gw_url.lower() not in ("none", "disabled", "off"):
        for _, app_no, mobile in rows:
            try:
                requests.post(
                    gw_url.rstrip("/") + "/api/send",
                    json={
                        "to": mobile,
                        "text": "Sewa Setu: your pension application %s stands approved "
                        "under the RTPS Act." % app_no,
                    },
                    timeout=5,
                )
            except Exception:
                pass
    print(
        "%s deemed approval: %d applications approved"
        % (current_dt.strftime("%Y-%m-%d %H:%M:%S"), len(rows)),
        flush=True,
    )
    cur.close()
    conn.close()
    return len(rows)


def _seconds_until_next_run():
    """Return sleep duration in seconds until next scheduled run (02:00 IST daily by default)."""
    custom_interval = os.environ.get("SCHEDULER_INTERVAL_SECONDS", "").strip()
    if custom_interval.isdigit() and int(custom_interval) > 0:
        return int(custom_interval)
    now = now_ist()
    target = now.replace(hour=2, minute=0, second=0, microsecond=0)
    if target <= now:
        target += timedelta(days=1)
    return max(60, int((target - now).total_seconds()))


def run_daemon():
    """Run deemed-approval job continuously as a single-worker background service."""
    print("Starting Sewa Setu deemed-approval scheduler worker...", flush=True)
    while True:
        try:
            main()
            break
        except Exception as exc:
            sys.stderr.write("Initial deemed-approval run waiting for database: %s\n" % exc)
            time.sleep(5)

    while True:
        sleep_secs = _seconds_until_next_run()
        time.sleep(sleep_secs)
        try:
            main()
        except Exception as exc:
            sys.stderr.write("Scheduled deemed-approval error: %s\n" % exc)


if __name__ == "__main__":
    if "--daemon" in sys.argv or os.environ.get("SCHEDULER_DAEMON", "").strip() in ("1", "true", "yes"):
        run_daemon()
    else:
        sys.exit(0 if main() >= 0 else 1)

