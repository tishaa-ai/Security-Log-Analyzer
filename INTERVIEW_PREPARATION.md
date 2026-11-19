# Interview Preparation – Security Log Analyzer & Alert Triage Dashboard

Use this guide to explain the project confidently. Every number below comes from running the
bundled **synthetic** datasets with the default settings.

---

## 1. Project explanation (plain language)

I built a small SOC tool that does what a Tier-1 analyst does with raw logs:

1. **Collect** – upload JSON or Syslog files (application auth logs, SSH logs, web access logs).
2. **Normalise** – convert every record into one common event shape (time, IP, user, type, HTTP
   status, path, message) and reject bad records with a reason.
3. **Detect** – run seven transparent rules: brute force, success after failures, password
   spraying, unusual login time, watchlisted IPs, HTTP 401/403 bursts and web scanning.
4. **Prioritise** – give each alert a rule-based severity and an explainable 0–100 risk score.
5. **Investigate** – show evidence, recommended steps and MITRE ATT&CK context; let the analyst
   change status and write notes, with an audit trail.
6. **Report** – export CSV, JSON and a PDF incident report.

Everything runs locally with SQLite. It never scans or blocks IPs, and it always labels alerts
as *indicators that need validation*, not confirmed attacks.

---

## 2. Architecture explanation

- **`parsers/`** – `ingest.py` decodes bytes, rejects binary/oversized/unsupported files and picks
  a parser. `json_parser.py` handles arrays, wrapper objects and JSON Lines using a field-alias
  table plus nested-key flattening (`source.ip`). `syslog_parser.py` uses regexes for RFC 3164,
  RFC 5424, ISO syslog and Apache/Nginx access logs, then regexes for message content (sshd, PAM,
  generic “login failed for user X from IP”).
- **`database.py`** – SQLite schema: `uploaded_files`, `events`, `rejected_records`, `alerts`,
  `alert_status_history`, `alert_notes`, `analysis_runs`, `settings`. One connection per
  operation, foreign keys on, parameterised queries only.
- **`detection/`** – `rules.py` measures facts using pandas and sliding windows; `severity.py`
  turns facts into a severity; `scoring.py` produces the risk score with an itemised explanation;
  `engine.py` adds correlation, deterministic alert IDs and prioritisation.
- **`pipeline.py`** – the glue: `ingest_file`, `run_analysis`, `load_sample_data`.
- **`reports/`** – builds one report dictionary, rendered to CSV, JSON or PDF.
- **`dashboard/`** – Streamlit views, Plotly charts and the dark theme.

Key design choice: **separation of concerns**. Rules don’t decide severity, severity doesn’t
compute risk, and the UI never contains detection logic – so each part is testable on its own.

---

## 3. Two-minute interview pitch

> “I built a Security Log Analyzer and Alert Triage Dashboard in Python to practise the work a
> SOC analyst does every day. It ingests JSON and Syslog files – including SSH auth logs, app
> login logs and web access logs – normalises them into one schema and rejects malformed records
> with clear reasons. On top of that I wrote seven configurable detection rules: repeated failed
> logins, a successful login after failures, password spraying across many accounts, off-hours
> logins, matches against a local IP watchlist, bursts of HTTP 401/403 responses, and web
> scanning or exploit-like requests.
>
> Each alert gets a rule-based severity and a deterministic risk score where every point is
> explained, so an analyst can see *why* something is P1. Alerts carry evidence, recommended
> investigation steps and a MITRE ATT&CK mapping – but only when the evidence supports one; for
> example, an off-hours login or a watchlist hit deliberately gets no technique.
>
> Analysts can move alerts through New, Investigating, Resolved or False Positive with an audit
> trail and notes, and export CSV, JSON or PDF reports – the CSV is protected against formula
> injection. Everything is stored in SQLite with duplicate-upload protection, and the project has
> a 135-test pytest suite, including headless tests of every dashboard page. On my synthetic
> dataset it processes 301 records, rejects 12 malformed ones and raises 19 prioritised alerts,
> with the two Critical alerts being brute-force-then-success scenarios.”

---

## 4. Thirty technical questions and answers

**Parsing & ingestion**

1. **Why normalise events into one schema?**
   Rules can then work on any source. A failed SSH password and a failed web-portal login both
   become `auth_failure` with `source_ip` and `username`, so one brute-force rule covers both.

2. **How do you handle different JSON field names?**
   An alias table (`FIELD_ALIASES`) lists common names per field (`src_ip`, `client_ip`,
   `source.ip`…). Nested objects are flattened to dotted keys first, then the first non-empty
   alias wins.

3. **How do you tell JSON from JSON Lines?**
   Try `json.loads` on the whole text. If that fails, parse line by line, so one broken line is
   rejected without losing the rest of the file.

4. **What syslog formats are supported and how?**
   RFC 3164, RFC 5424, ISO-timestamped rsyslog and Apache/Nginx access logs, each with an
   anchored regex for the header. A second set of regexes extracts security fields from the
   message (sshd Failed/Accepted, PAM failures, generic login messages, embedded access logs).

5. **RFC 3164 has no year. How do you handle that?**
   The year is an explicit input (an upload form field; samples use 2026). Guessing from “now”
   breaks around New Year and when old logs are re-analysed.

6. **What makes a record “rejected”?**
   Missing or unparseable timestamp, an invalid IP (e.g. `999.10.1.5`), an invalid HTTP status,
   a non-object JSON value, an empty object, a broken JSON line, an unrecognised syslog line, or a
   record with no usable fields. Rejected records are stored with the reason and shown in the UI.

7. **Why reject invalid IPs instead of ignoring them?**
   A malformed IP suggests a corrupted or tampered record. Silently dropping the field could
   hide the event from IP-based rules; rejecting it makes the problem visible.

8. **How is duplicate upload prevented?**
   Two layers: a SHA-256 of the file content (`uploaded_files.file_hash UNIQUE`) skips identical
   files, and each event gets a hash of its raw text plus occurrence number (`events.event_hash
   UNIQUE` with `INSERT OR IGNORE`), so overlapping files don’t duplicate events while genuinely
   repeated lines inside one file are kept.

9. **Why might sshd “Invalid user” lines be informational only?**
   sshd logs both “Invalid user X” and “Failed password for invalid user X” for one attempt.
   Counting both would double the failures and inflate brute-force alerts.

10. **How do you handle timezones?**
    Aware timestamps are converted to UTC; naive ones are assumed to be UTC. Everything is stored
    as `YYYY-MM-DD HH:MM:SS` UTC, which also sorts correctly as text.

**Detection**

11. **How does the brute-force rule work?**
    Group `auth_failure` events by IP, split them into bursts where gaps are larger than the
    window, then use a two-pointer sliding window to find the peak count inside any 10-minute
    span. Peak ≥ 5 → Medium, ≥ 10 → High.

12. **Why a sliding window and not fixed buckets?**
    Fixed 10-minute buckets miss an attack split across a boundary (3 failures at 10:08, 3 at
    10:11). A sliding window finds the true peak.

13. **How does “success after failures” avoid repeated alerts?**
    For each success it counts failures from the same IP in the previous 30 minutes, but only
    failures after the last alerted success (`consumed_until`), so the same failures are never
    reused.

14. **How do you detect password spraying?**
    Count *distinct usernames* among one IP’s failures in a sliding window with a counter
    (AUTH-003). Many accounts with few attempts each is the spraying pattern, which per-account
    lockout rules often miss.

15. **How is an unusual login time defined?**
    A success outside configurable business hours (default 07:00–20:00 UTC, overnight shifts
    supported) or at a weekend. Privileged accounts raise severity from Low to Medium.

16. **How is the watchlist matched safely?**
    Entries are parsed with `ipaddress.ip_network` (single IPs and CIDRs); invalid entries are
    reported and ignored. Matching is purely local – no DNS, WHOIS, threat-intel API or scanning –
    and there is no automatic blocking.

17. **What does the HTTP-001 rule detect?**
    Bursts of 401/403 responses per IP. It maps to T1110 only when most responses are 401s on
    login-like paths; repeated 403s on `/admin` are access-control denials and get no technique.

18. **What does HTTP-002 detect?**
    Path enumeration (many distinct paths, mostly errors), probing of ≥ 2 sensitive paths
    (`/.env`, `/.git/config`, `/phpmyadmin`…), and exploit-like strings (traversal `../`,
    `/etc/passwd`, SQL injection patterns, `${jndi:`). URL-decoding runs first so `%27` is caught.

19. **Why are alert IDs deterministic?**
    The ID is a hash of rule + key facts (IP, first-seen time, user). Re-running detection
    updates the same alert instead of creating duplicates, which keeps analyst status and notes
    attached.

20. **How do you limit false positives?**
    Thresholds over time windows, ignoring single typos (one failure then success), requiring ≥ 2
    sensitive paths, separating rules for different behaviours, and showing every alert as an
    indicator with evidence so an analyst can close it as a False Positive.

**Severity, scoring & MITRE**

21. **What is the difference between severity and risk score?**
    Severity is a categorical, rule-specific judgement (e.g. success after ≥ 5 failures on the
    same account = Critical). Risk score adds context across rules – volume, watchlist,
    privileged account, a successful login, correlation – to rank alerts within and across
    severities.

22. **How is the risk score explainable?**
    It is a sum of named factors (`Base score for High severity +65`, `Source IP is on the local
    watchlist +10`…) capped at 100. The factors are stored with the alert and charted in the UI.
    No randomness, no hidden model.

23. **What is correlation in your scoring?**
    If other rules fired for the same IP, the score gets +5 per additional rule (max +10).
    Example: 203.0.113.45 triggers AUTH-001, AUTH-002, AUTH-004 and NET-001, so each of those
    alerts ranks higher.

24. **Why does the watchlist rule have no MITRE mapping?**
    Being on a list is reputation, not behaviour. ATT&CK describes adversary behaviour, so
    mapping a list hit to a technique would claim more than the evidence shows.

25. **Why map AUTH-002 to both T1110 and T1078?**
    The failures are consistent with Brute Force; the subsequent success is consistent with use
    of Valid Accounts. It is still only *consistent with* – the user may simply have mistyped
    their password.

**Engineering & security**

26. **How do you protect CSV exports?**
    Any text cell starting with `=`, `+`, `-`, `@`, tab, CR, `|` or `%` is prefixed with `'`, so
    Excel/Sheets treat it as text. Attackers control log content (usernames, URLs), so this
    matters.

27. **How do you avoid SQL injection?**
    Every query uses parameter placeholders (`?` or `:name`); user input is never formatted into
    SQL strings.

28. **How does the UI avoid HTML injection?**
    Values shown inside custom HTML (badges, headers) go through `html.escape`; tables use
    Streamlit components that render text, not HTML.

29. **How did you test the dashboard?**
    Streamlit’s `AppTest` runs `app.py` headlessly for every page, both with an empty and a
    populated database, checks for exceptions, verifies that metrics equal database values, and
    clicks real buttons (load samples, change status).

30. **How would you scale this?**
    Stream parsing in chunks, push detection into SQL or a columnar engine (DuckDB), move to a
    server database, add incremental detection (only new events), schedule runs, and add
    authentication/RBAC for multiple analysts.

---

## 5. SOC alert investigation examples (from the sample data)

**Example A – AUTH-002, Critical, risk 100: 203.0.113.12 / root**
- Evidence: 9 × `Failed password for root` from 03:02:00–03:04:40, then `Accepted password for
  root` at 03:05:30 (bastion01, SSH).
- Correlated: AUTH-001 (brute force), AUTH-004 (03:05 is off-hours, privileged account),
  NET-001 (inside watchlisted 203.0.113.0/28).
- Steps: confirm with the root key holders; review commands run in that session (auditd, shell
  history); check new users/keys/cron jobs; if unconfirmed, treat as compromise – rotate the
  credential, disable password auth for root, escalate. Status → Investigating, add notes.

**Example B – AUTH-003, High: 198.51.100.77 password spraying**
- Evidence: 8 different accounts, one failure each, 40 s apart at 13:05.
- No success from that IP, so not Critical.
- Steps: confirm none of the 8 accounts logged in from that IP later; check lockouts; check
  whether `grace`/`heidi` are real accounts (attacker reconnaissance); document and recommend
  perimeter controls through change management.

**Example C – HTTP-002, High: 198.51.100.23 scanning**
- Evidence: 22 distinct paths in ~3 minutes, all 403/404, including `/.env`, `/.git/config`,
  `/backup.sql`, `/static/../../../../etc/passwd` and a SQL-injection query string.
- Steps: verify none of these returned 200; confirm `.env`/`.git` are not reachable; check
  application errors at 15:10. Likely automated reconnaissance; resolve if no exposure.

**Example D – AUTH-004, Low: bob at 23:40 from 192.0.2.11**
- Bob’s usual IP, no failures, no other rules → probably legitimate overtime.
- Steps: quick confirmation with bob or his manager → **False Positive** with a note.
  This shows why the tool calls alerts indicators.

---

## 6. Detection rule explanations (one-liners)

| Rule | What it means | Typical benign cause |
|---|---|---|
| AUTH-001 | Many failures from one IP in a short time | User with a saved wrong password, misconfigured service account |
| AUTH-002 | Failures then success from the same IP | User forgot then remembered the password |
| AUTH-003 | Failures across many accounts from one IP | Shared NAT/VPN gateway, SSO outage |
| AUTH-004 | Success outside business hours/weekend | On-call or overtime work |
| NET-001 | Activity from a watchlisted IP/CIDR | Stale watchlist entry, reassigned IP |
| HTTP-001 | Burst of 401/403 for one client | Expired token in an app retry loop |
| HTTP-002 | Enumeration, sensitive paths, exploit strings | Authorised vulnerability scanner |

---

## 7. MITRE ATT&CK mapping explanations

| Technique | Used by | Why it applies |
|---|---|---|
| **T1110 Brute Force** | AUTH-001 (multi-account), AUTH-002, HTTP-001 (401s on login paths) | Repeated authentication attempts to obtain access |
| **T1110.001 Password Guessing** | AUTH-001 (≤ 2 accounts) | Many passwords tried against one/few accounts |
| **T1110.003 Password Spraying** | AUTH-003 | Few passwords tried across many accounts |
| **T1078 Valid Accounts** | AUTH-002 | Success after failures is consistent with use of a guessed credential |
| **T1595.003 Wordlist Scanning** | HTTP-002 | Requests for many/well-known paths = content discovery |
| **T1190 Exploit Public-Facing Application** | HTTP-002 (exploit strings) | Traversal/injection payloads are *attempts*; success is not implied |
| *(none)* | AUTH-004, NET-001, HTTP-001 403-only | Timing, reputation or access denials don’t show a technique |

**Indicator vs. confirmed attack:** a mapping says “this behaviour matches technique X”. Only an
investigation (contacting the user, reviewing session activity, host forensics) can confirm an
attack.

---

## 8. Troubleshooting scenarios

| Symptom | Cause | Fix |
|---|---|---|
| `Activate.ps1 cannot be loaded because running scripts is disabled` | PowerShell execution policy | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`, then activate again |
| `streamlit : The term 'streamlit' is not recognized` | venv not activated | `.\.venv\Scripts\Activate.ps1` or run `python -m streamlit run app.py` |
| Upload says “Unsupported file type” | Extension not in .json/.jsonl/.ndjson/.log/.txt/.syslog | Rename the file or export in a supported format |
| All lines rejected, “Unsupported format” | Wrong format chosen or an unknown log layout | Use *Auto-detect*; check the rejected-records table for reasons |
| Syslog events appear in the wrong year | RFC 3164 has no year | Set “Year for syslog lines without a year” before uploading |
| “identical file already ingested” | Duplicate protection | Expected – nothing is stored twice |
| No alerts after upload | Detection not run or thresholds too high | Click **Run detection now**; check thresholds and enabled rules in Settings |
| Port 8501 already in use | Another Streamlit instance | `streamlit run app.py --server.port 8502` |
| Want a clean start | Old data in SQLite | Settings → Danger zone → type `RESET` (only deletes this app’s data) |

---

## 9. Limitations and future improvements

**Limitations**
- Static thresholds; no per-user baselines or anomaly detection.
- Batch analysis over all events in memory; not built for SIEM-scale data.
- Alias-based field mapping; unusual schemas need new aliases.
- Single global business-hours window in UTC.
- Local single-user app without authentication.

**Future improvements**
- Per-user/per-host baselines (usual hours, usual IPs, impossible travel with offline GeoIP).
- Sigma rule import so detections can be shared in a standard format.
- Incremental/streaming ingestion and scheduled detection.
- Case management: group related alerts into incidents, assign owners, SLAs.
- Authentication and role-based access for multiple analysts.
- Windows Event Log (EVTX) and cloud audit-log (CloudTrail, Entra ID) parsers.
- Enrichment from approved, offline threat-intel feeds (still without active scanning).
