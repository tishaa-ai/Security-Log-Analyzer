"""Generate the SYNTHETIC sample datasets in ``data/samples``.

All data is fictional:
* IP addresses come only from documentation ranges (RFC 5737):
  192.0.2.0/24 (normal users), 198.51.100.0/24 and 203.0.113.0/24 (suspicious).
* Hostnames use the reserved ``example.com`` domain.
* Usernames are generic placeholders.

Output is deterministic (fixed random seed) so tests and documentation stay
consistent. Run from the project root:

    .venv\\Scripts\\python.exe scripts\\generate_sample_data.py
"""

from __future__ import annotations

import json
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from config import DATA_DIR, SAMPLES_DIR  # noqa: E402

DAY = datetime(2026, 11, 18)  # a Wednesday
NOTICE = ("SYNTHETIC DATA - generated for training/testing the Security Log Analyzer. "
          "Not real logs. IPs are RFC 5737 documentation addresses.")
rng = random.Random(42)

NORMAL_USERS = {
    "alice": "192.0.2.10", "bob": "192.0.2.11", "carol": "192.0.2.12",
    "dave": "192.0.2.13", "erin": "192.0.2.14", "frank": "192.0.2.15",
}


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def bsd(dt: datetime) -> str:
    return dt.strftime("%b %d %H:%M:%S").replace(" 0", "  ", 1) if dt.day < 10 else dt.strftime("%b %d %H:%M:%S")


# ---------------------------------------------------------------------------
# 1) Application authentication log (JSON wrapper object)
# ---------------------------------------------------------------------------
def app_auth_events() -> list[object]:
    events: list[object] = []

    def auth(ts: datetime, user: str, ip: str, outcome: str, msg: str | None = None) -> dict:
        return {
            "timestamp": iso(ts),
            "event_type": "user_login",
            "outcome": outcome,
            "username": user,
            "source_ip": ip,
            "service": "customer-portal",
            "hostname": "app01.example.com",
            "message": msg or f"User login {outcome} for {user}",
        }

    # Normal business-hours activity (two logins per user, some logouts).
    for user, ip in NORMAL_USERS.items():
        for hour in (8, 13):
            ts = DAY.replace(hour=hour, minute=rng.randint(0, 50), second=rng.randint(0, 59))
            events.append(auth(ts, user, ip, "success"))
            events.append({
                "timestamp": iso(ts + timedelta(hours=3, minutes=rng.randint(0, 30))),
                "event_type": "user_logout", "username": user, "source_ip": ip,
                "service": "customer-portal", "message": f"User {user} logged out",
            })

    # Single typo then success (normal - must NOT trigger AUTH-002 at threshold 3).
    t = DAY.replace(hour=9, minute=41, second=5)
    events.append(auth(t, "dave", NORMAL_USERS["dave"], "failure", "Invalid password for dave"))
    events.append(auth(t + timedelta(seconds=20), "dave", NORMAL_USERS["dave"], "success"))

    # ECS-style nested records (shows alias + nested-field support).
    for user, minute in (("erin", 15), ("frank", 32)):
        events.append({
            "@timestamp": iso(DAY.replace(hour=10, minute=minute)),
            "event": {"action": "authentication", "outcome": "success"},
            "user": {"name": user},
            "source": {"ip": NORMAL_USERS[user]},
            "host": {"name": "sso01.example.com"},
            "message": "SSO authentication succeeded",
        })

    # Scenario A: brute force against 'admin' then success at night (203.0.113.45).
    start = DAY.replace(hour=2, minute=14, second=0)
    for i in range(12):
        events.append(auth(start + timedelta(seconds=25 * i), "admin", "203.0.113.45", "failure",
                           "Login failed for admin: bad password"))
    events.append(auth(start + timedelta(minutes=6, seconds=10), "admin", "203.0.113.45", "success",
                       "Login success for admin"))

    # Scenario B: password spraying across many accounts (198.51.100.77).
    spray_users = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi"]
    start = DAY.replace(hour=13, minute=5, second=0)
    for i, user in enumerate(spray_users):
        events.append(auth(start + timedelta(seconds=40 * i), user, "198.51.100.77", "failure",
                           f"Login failed for {user}: bad password"))

    # Scenario C: legitimate-looking but late-night login (off-hours, non-privileged).
    events.append(auth(DAY.replace(hour=23, minute=40, second=12), "bob", NORMAL_USERS["bob"], "success"))

    # Malformed / incomplete records for parser validation.
    events.extend([
        {"event_type": "user_login", "outcome": "failure", "username": "eve", "source_ip": "192.0.2.50"},
        {"timestamp": iso(DAY.replace(hour=11)), "event_type": "user_login", "outcome": "failure",
         "username": "mallory", "source_ip": "999.10.1.5"},
        {"timestamp": "yesterday afternoon", "event_type": "user_login", "username": "trent",
         "source_ip": "192.0.2.51"},
        "corrupted-record-not-an-object",
        {},
    ])
    return events


# ---------------------------------------------------------------------------
# 2) Web access log (JSON Lines)
# ---------------------------------------------------------------------------
def web_access_lines() -> list[str]:
    records: list[dict] = []
    agents = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0)"]
    normal_paths = ["/", "/products", "/products/42", "/cart", "/api/session", "/static/app.js",
                    "/static/style.css", "/help", "/account"]

    def req(ts: datetime, ip: str, method: str, path: str, status: int, user: str | None = None) -> dict:
        record = {"time": iso(ts), "client_ip": ip, "method": method, "path": path, "status": status,
                  "bytes": rng.randint(200, 9000), "user_agent": rng.choice(agents),
                  "host": "web01.example.com"}
        if user:
            record["user"] = user
        return record

    # Normal browsing throughout the day.
    for _ in range(140):
        ts = DAY.replace(hour=rng.randint(7, 19), minute=rng.randint(0, 59), second=rng.randint(0, 59))
        ip = f"192.0.2.{rng.randint(20, 29)}"
        records.append(req(ts, ip, "GET", rng.choice(normal_paths), rng.choice([200] * 12 + [304, 404])))

    # A user occasionally hitting a forbidden admin page (benign, below threshold).
    for i in range(3):
        records.append(req(DAY.replace(hour=11, minute=10 + i), "192.0.2.30", "GET", "/admin", 403, "carol"))

    # Scenario D: web login brute force -> many 401s on /api/login (203.0.113.99).
    start = DAY.replace(hour=9, minute=30, second=0)
    for i in range(25):
        records.append(req(start + timedelta(seconds=7 * i), "203.0.113.99", "POST", "/api/login", 401))

    # Scenario E: content discovery / probing with exploit-like strings (198.51.100.23).
    scan_paths = [
        "/.env", "/.git/config", "/wp-admin/", "/wp-login.php", "/phpmyadmin/", "/backup.sql",
        "/config.php", "/server-status", "/old/", "/test/", "/dev/", "/api/v1/users", "/api/v2/",
        "/uploads/", "/cgi-bin/", "/admin.php", "/login.jsp", "/debug", "/console", "/.aws/credentials",
        "/static/../../../../etc/passwd", "/search?q=%27%20OR%20%271%27%3D%271",
    ]
    start = DAY.replace(hour=15, minute=10, second=0)
    for i, path in enumerate(scan_paths):
        status = 403 if path.startswith(("/.", "/wp", "/php", "/server", "/config")) else 404
        records.append(req(start + timedelta(seconds=9 * i), "198.51.100.23", "GET", path, status))

    records.sort(key=lambda r: r["time"])
    lines = [json.dumps(r) for r in records]

    # Malformed lines for parser validation.
    lines.insert(10, '{"time": "2026-11-18T10:00:00Z", "client_ip": "192.0.2.20", "method": "GET"')
    lines.insert(50, json.dumps({"time": iso(DAY.replace(hour=12)), "client_ip": "192.0.2.21",
                                 "method": "GET", "path": "/", "status": 999}))
    lines.insert(90, json.dumps({"time": iso(DAY.replace(hour=13)), "client_ip": "256.1.1.1",
                                 "method": "GET", "path": "/", "status": 200}))
    return [f"# {NOTICE}"] + lines


# ---------------------------------------------------------------------------
# 3) Linux auth / syslog (mixed RFC 3164, RFC 5424, ISO and access-log lines)
# ---------------------------------------------------------------------------
def syslog_lines() -> list[str]:
    entries: list[tuple[datetime, str]] = []
    host = "bastion01"
    pid = iter(range(4100, 9999))

    def sshd(ts: datetime, msg: str) -> None:
        entries.append((ts, f"<38>{bsd(ts)} {host} sshd[{next(pid)}]: {msg}"))

    # Normal key-based logins during business hours.
    for user, ip in NORMAL_USERS.items():
        ts = DAY.replace(hour=rng.randint(8, 17), minute=rng.randint(0, 59), second=rng.randint(0, 59))
        sshd(ts, f"Accepted publickey for {user} from {ip} port {rng.randint(40000, 60000)} ssh2")

    # Scenario F: SSH brute force on root, then success (203.0.113.12, watchlisted /28).
    start = DAY.replace(hour=3, minute=2, second=0)
    for i in range(9):
        sshd(start + timedelta(seconds=20 * i),
             f"Failed password for root from 203.0.113.12 port {50000 + i} ssh2")
    sshd(start + timedelta(minutes=3, seconds=30), "Accepted password for root from 203.0.113.12 port 50100 ssh2")

    # Scenario G: invalid-user sweep across many accounts (198.51.100.200).
    start = DAY.replace(hour=21, minute=30, second=0)
    for i, user in enumerate(["test", "oracle", "guest", "ubuntu", "postgres"]):
        ts = start + timedelta(seconds=45 * i)
        sshd(ts, f"Invalid user {user} from 198.51.100.200 port {41000 + i}")
        sshd(ts + timedelta(seconds=2),
             f"Failed password for invalid user {user} from 198.51.100.200 port {41000 + i} ssh2")

    # PAM failure from a local 'su' attempt (no remote host).
    ts = DAY.replace(hour=14, minute=22, second=10)
    entries.append((ts, f"<85>{bsd(ts)} {host} su[{next(pid)}]: pam_unix(su:auth): authentication failure; "
                        "logname=dave uid=1001 euid=0 tty=pts/0 ruser=dave rhost=  user=root"))

    # Cron / system noise.
    for hour in range(0, 24, 4):
        ts = DAY.replace(hour=hour, minute=17)
        entries.append((ts, f"<78>{bsd(ts)} {host} CRON[{next(pid)}]: (root) CMD (run-parts /etc/cron.hourly)"))

    # RFC 5424 application auth messages.
    for minute, result, user in ((0, "failed", "carol"), (1, "succeeded", "carol")):
        ts = DAY.replace(hour=11, minute=minute)
        entries.append((ts, f"<38>1 {iso(ts)} app02.example.com webportal 2211 AUTH - "
                            f"login {result} for user '{user}' from 192.0.2.12"))

    # ISO-timestamped rsyslog lines.
    ts = DAY.replace(hour=12, minute=5, second=33)
    entries.append((ts, f"{ts.strftime('%Y-%m-%dT%H:%M:%S')}+00:00 {host} sshd[{next(pid)}]: "
                        "Accepted publickey for erin from 192.0.2.14 port 50022 ssh2"))

    # Scenario H: repeated 403s on /admin from one client via nginx (203.0.113.140).
    start = DAY.replace(hour=16, minute=20, second=1)
    for i in range(12):
        ts = start + timedelta(seconds=10 * i)
        entries.append((ts, f"<190>{bsd(ts)} web02 nginx: 203.0.113.140 - - "
                            f"[{ts.strftime('%d/%b/%Y:%H:%M:%S')} +0000] \"GET /admin HTTP/1.1\" 403 153 "
                            "\"-\" \"Mozilla/5.0\""))

    # Scenario I: weekend login (Saturday) by a normal user.
    ts = datetime(2026, 11, 21, 10, 15, 7)
    sshd(ts, "Accepted publickey for carol from 192.0.2.12 port 51515 ssh2")

    entries.sort(key=lambda e: e[0])
    lines = [line for _, line in entries]

    # Malformed lines for parser validation.
    lines.insert(5, "this is not a syslog line at all")
    lines.insert(12, f"<38>Nov 18 25:61:00 {host} sshd[1]: Failed password for bob from 192.0.2.11 port 22 ssh2")
    lines.insert(20, f"<38>Nov 18 10:00:00 {host} sshd[2]: Failed password for bob from 300.1.2.3 port 22 ssh2")
    lines.insert(30, "<13>Nov 18")
    return [f"# {NOTICE}"] + lines


def main() -> None:
    SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
    app_doc = {"_synthetic_notice": NOTICE, "source": "customer-portal auth log (synthetic)",
               "events": app_auth_events()}
    (SAMPLES_DIR / "sample_app_auth.json").write_text(json.dumps(app_doc, indent=2), encoding="utf-8")
    (SAMPLES_DIR / "sample_web_access.jsonl").write_text("\n".join(web_access_lines()) + "\n", encoding="utf-8")
    (SAMPLES_DIR / "sample_linux_auth.log").write_text("\n".join(syslog_lines()) + "\n", encoding="utf-8")
    (DATA_DIR / "watchlist.txt").write_text(
        "# Local IP watchlist (SYNTHETIC). One IP or CIDR per line. Used for matching only -\n"
        "# the analyzer never scans or blocks these addresses.\n"
        "203.0.113.45      # brute-force source seen in previous incident (synthetic)\n"
        "203.0.113.0/28    # documentation range flagged by threat-intel exercise (synthetic)\n"
        "198.51.100.77     # password-spraying source (synthetic)\n"
        "198.51.100.200    # SSH invalid-user sweep source (synthetic)\n"
        "192.0.2.250       # watchlisted but no activity expected\n",
        encoding="utf-8",
    )
    print(f"Sample data written to {SAMPLES_DIR}")


if __name__ == "__main__":
    main()
