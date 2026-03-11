# 🔍 Log Analyzer — Suspicious Activity Detection

> A professional-grade CLI tool that parses SSH, web server, and Windows event logs to detect brute force attacks, injection attempts, port scans, and privilege escalation — all with colored terminal output and structured JSON reports.

---

## 📸 Preview

```
╔══════════════════════════════════════╗
║     LOG ANALYZER — SECURITY REPORT  ║
╚══════════════════════════════════════╝

[CRITICAL] Successful Login After Brute Force
           IP: 192.168.1.45 | Time: 2024-01-15 03:42:11
           Details: 47 failed attempts then success at 3:42am

[HIGH]     Brute Force Detected
           IP: 10.0.0.23 | Attempts: 142 in 8 minutes
           Targeted User: admin

[MEDIUM]   SQL Injection Attempt
           IP: 203.45.67.89 | URL: /login?id=1' OR '1'='1
           User Agent: sqlmap/1.7

══════════════════════════════════════
SUMMARY
══════════════════════════════════════
Total Events Analyzed : 15,432
Suspicious Events     : 89
Unique Attacker IPs   : 12
CRITICAL              : 2  🔴
HIGH                  : 8  🟠
MEDIUM                : 23 🟡
LOW                   : 56 🔵
```

---

## ⚡ Quickstart

```bash
# Install the only dependency
pip install colorama

# Analyze all sample logs at once
python main.py --type all --dir sample_logs/

# Analyze a specific SSH log
python main.py --type ssh --file sample_logs/auth.log

# Filter by severity and save a JSON report
python main.py --type web --file sample_logs/access.log --severity HIGH --output report.json
```

---

## 🧠 What It Detects

### SSH / Auth Logs (`/var/log/auth.log`)
| Threat | Condition |
|--------|-----------|
| Brute Force | 5+ failed logins from same IP within 10 minutes |
| Root Login Attempts | Any `Failed password for root` entry |
| Invalid User | `Invalid user` entries logged |
| Successful Login After Failures | Possible account compromise |
| Off-Hours Access | Successful login between 11pm – 5am |

### Web Server Logs (Apache / Nginx)
| Threat | Condition |
|--------|-----------|
| SQL Injection | Patterns like `' OR 1=1`, `UNION SELECT` in URLs |
| XSS Attempts | `<script>`, `alert()`, `javascript:` in request paths |
| Directory Traversal | `../../../` sequences detected |
| Scanner Detection | Tools like `nikto`, `sqlmap`, `masscan` in User-Agent |
| 404 Flooding | 20+ 404s from one IP within 1 minute |
| High Request Rate | 100+ requests from one IP within 1 minute |
| Unusual HTTP Methods | `TRACE`, `CONNECT`, `DELETE` from unknown IPs |

### Windows Event Logs (JSON format)
| Event ID | Meaning | Detection |
|----------|---------|-----------|
| 4625 | Failed logon | Multiple = brute force |
| 4648 | Logon with explicit credentials | Flagged for review |
| 4720 | New user account created | Flagged |
| 4732 | User added to privileged group | 4720 + 4732 sequence = privilege escalation |
| 7045 | New service installed | Flagged as suspicious |
| 4698 | Scheduled task created | Flagged |

---

## 🗂️ Project Structure

```
log-analyzer/
├── main.py                    ← CLI entry point (argparse)
├── analyzer/
│   ├── base_analyzer.py       ← Abstract base class
│   ├── ssh_analyzer.py        ← Parses auth/SSH logs
│   ├── web_analyzer.py        ← Parses Apache/Nginx logs
│   └── windows_analyzer.py   ← Parses Windows event logs (JSON)
├── detectors/
│   ├── brute_force.py         ← Brute force detection logic
│   ├── port_scan.py           ← Port scan detection
│   └── anomaly.py             ← Unusual pattern detection
├── reporter/
│   ├── terminal_report.py     ← Colored terminal output (colorama)
│   └── json_report.py         ← Structured JSON report writer
├── sample_logs/
│   ├── auth.log               ← Sample SSH log with fake attacks
│   ├── access.log             ← Sample Apache log with injection attempts
│   └── windows.evtx.json      ← Sample Windows events (JSON)
├── requirements.txt
└── README.md
```

---

## 🖥️ CLI Reference

```
python main.py [OPTIONS]
```

| Argument | Values | Description |
|----------|--------|-------------|
| `--type` | `ssh`, `web`, `windows`, `all` | Log format to analyze |
| `--file` | path | Single log file to analyze |
| `--dir` | path | Directory of logs (use with `--type all`) |
| `--output` | path | Save findings to JSON file |
| `--severity` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` | Filter output by minimum severity |
| `--threshold` | integer | Brute force attempt threshold (default: 5) |

**Examples:**
```bash
python main.py --type ssh     --file sample_logs/auth.log
python main.py --type web     --file sample_logs/access.log
python main.py --type windows --file sample_logs/windows.evtx.json
python main.py --type all     --dir  sample_logs/
python main.py --type web     --file access.log --severity HIGH --output report.json
python main.py --type ssh     --file auth.log   --threshold 10
```

---

## 📊 Severity Levels

| Level | Color | Meaning |
|-------|-------|---------|
| `CRITICAL` | 🔴 Red background | Active compromise indicators |
| `HIGH` | 🟠 Red text | Brute force, privilege escalation |
| `MEDIUM` | 🟡 Yellow text | Scanning, repeated failures |
| `LOW` | 🔵 Cyan text | Off-hours access, unusual agents |
| `INFO` | ⚪ White text | General statistics |

---

## 📄 JSON Report Format

```json
{
  "report_generated": "2024-01-15T14:23:00",
  "log_file": "auth.log",
  "log_type": "ssh",
  "total_lines_analyzed": 15432,
  "summary": {
    "total_suspicious": 89,
    "unique_ips": 12,
    "critical": 2,
    "high": 8,
    "medium": 23,
    "low": 56
  },
  "findings": [
    {
      "severity": "HIGH",
      "type": "brute_force",
      "ip": "10.0.0.23",
      "timestamp": "2024-01-15T03:42:11",
      "details": "142 failed attempts in 8 minutes",
      "targeted_user": "admin",
      "recommendation": "Block IP immediately, check if login succeeded"
    }
  ],
  "top_attacker_ips": ["10.0.0.23", "192.168.1.45"],
  "recommendations": [
    "Block 3 IPs immediately",
    "Enable fail2ban for SSH",
    "Review admin account for compromise"
  ]
}
```

---

## 🛠️ Tech Stack

- **Language:** Python 3.10+
- **Dependencies:** `colorama` (terminal colors) — nothing else
- **Standard library:** `re`, `os`, `sys`, `json`, `datetime`, `collections`, `argparse`
- **Design patterns:** Abstract base class, dataclasses, pure functions

---

## 🔧 Installation

```bash
git clone https://github.com/ThejasRajamoney/log-analyzer
cd log-analyzer
pip install colorama
python main.py --type all --dir sample_logs/
```

---

## 🧪 Sample Logs

The `sample_logs/` directory includes pre-built realistic log files for immediate testing:

- **`auth.log`** — SSH log with a 50-attempt brute force sequence ending in a successful login, root login attempts from 3 IPs, and off-hours access
- **`access.log`** — Apache log with normal traffic mixed with SQL injection, directory traversal, sqlmap requests, and a 404 flood
- **`windows.evtx.json`** — Windows events with a 4625 brute force sequence, a 4720 + 4732 privilege escalation chain, and a suspicious 7045 service install

---

## 🗺️ Roadmap

- [ ] Live log tailing with `--watch` mode
- [ ] IP geolocation enrichment
- [ ] Slack / webhook alert integration
- [ ] HTML report export
- [ ] Docker container support

---

## ⚠️ Disclaimer

This tool is intended for **authorized security analysis and defensive monitoring only**. Only use it on systems and logs you own or have explicit permission to analyze.

---

*Part of the [50 Projects Challenge](https://github.com/ThejasRajamoney) — building one project in every language.*
