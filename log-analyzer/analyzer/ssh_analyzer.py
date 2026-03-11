import re
import os
from datetime import datetime
from .base_analyzer import BaseAnalyzer, Report, Finding, Severity

# Regex patterns for SSH
SSH_FAILED_PATTERN = r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+Failed password for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
SSH_ACCEPTED_PATTERN = r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+Accepted password for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
SSH_INVALID_USER_PATTERN = r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+Invalid user (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"

class SSHAnalyzer(BaseAnalyzer):
    def _parse_timestamp(self, month, day, time_str):
        current_year = datetime.now().year
        return datetime.strptime(f"{current_year} {month} {day} {time_str}", "%Y %b %d %H:%M:%S")

    def analyze(self) -> Report:
        report = Report(datetime.now(), self.file_path, "ssh", 0)
        failed_attempts = []
        successful_logins = []
        if not os.path.exists(self.file_path): return report
        with open(self.file_path, 'r') as f:
            for line in f:
                report.total_lines_analyzed += 1
                match_failed = re.search(SSH_FAILED_PATTERN, line)
                if match_failed:
                    ts = self._parse_timestamp(match_failed.group('month'), match_failed.group('day'), match_failed.group('time'))
                    failed_attempts.append({'ip': match_failed.group('ip'), 'timestamp': ts, 'user': match_failed.group('user')})
                    if "root" in match_failed.group('user'):
                        report.findings.append(Finding(Severity.HIGH, "root_login_attempt", ts, match_failed.group('ip'), "Failed password for root", "root", recommendation="Disable root SSH login."))
                    continue
                match_invalid = re.search(SSH_INVALID_USER_PATTERN, line)
                if match_invalid:
                    ts = self._parse_timestamp(match_invalid.group('month'), match_invalid.group('day'), match_invalid.group('time'))
                    failed_attempts.append({'ip': match_invalid.group('ip'), 'timestamp': ts, 'user': match_invalid.group('user')})
                    report.findings.append(Finding(Severity.MEDIUM, "invalid_user_attempt", ts, match_invalid.group('ip'), f"Unknown user: {match_invalid.group('user')}", match_invalid.group('user'), recommendation="Check for unauthorized users."))
                    continue
                match_accepted = re.search(SSH_ACCEPTED_PATTERN, line)
                if match_accepted:
                    ts = self._parse_timestamp(match_accepted.group('month'), match_accepted.group('day'), match_accepted.group('time'))
                    successful_logins.append({'ip': match_accepted.group('ip'), 'timestamp': ts, 'user': match_accepted.group('user')})
                    if ts.hour >= 23 or ts.hour < 5:
                        report.findings.append(Finding(Severity.LOW, "off_hours_login", ts, match_accepted.group('ip'), "Login during off-hours", match_accepted.group('user'), recommendation="Verify off-hours access."))
        
        ip_failed = {}
        for fa in failed_attempts:
            ip_failed[fa['ip']] = ip_failed.get(fa['ip'], []) + [fa['timestamp']]
        for ip, tss in ip_failed.items():
            if len(tss) >= self.threshold:
                report.findings.append(Finding(Severity.HIGH, "brute_force", tss[-1], ip, f"{len(tss)} failed attempts", recommendation="Block IP."))
        for sl in successful_logins:
            recent_fails = [t for t in ip_failed.get(sl['ip'], []) if sl['timestamp'] > t and (sl['timestamp'] - t).total_seconds() < 600]
            if len(recent_fails) >= self.threshold:
                report.findings.append(Finding(Severity.CRITICAL, "success_after_brute_force", sl['timestamp'], sl['ip'], f"Success after {len(recent_fails)} fails", sl['user'], recommendation="COMPROMISE LIKELY."))
        report.generate_summary()
        return report
