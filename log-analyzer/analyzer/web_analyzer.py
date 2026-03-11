import re
import os
from datetime import datetime
from .base_analyzer import BaseAnalyzer, Report, Finding, Severity

WEB_LOG_PATTERN = r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+-\s+-\s+\[(?P<timestamp>.*?)\]\s+"(?P<method>\w+)\s+(?P<url>.*?)\s+HTTP/.*?"\s+(?P<status>\d+)\s+(?P<size>\d+)\s+"(?P<referrer>.*?)"\s+"(?P<user_agent>.*?)"'

class WebAnalyzer(BaseAnalyzer):
    def _parse_timestamp(self, ts_str):
        ts_str = ts_str.split(' ')[0]
        return datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S")

    def analyze(self) -> Report:
        report = Report(datetime.now(), self.file_path, "web", 0)
        requests = []
        if not os.path.exists(self.file_path): return report
        with open(self.file_path, 'r') as f:
            for line in f:
                report.total_lines_analyzed += 1
                match = re.search(WEB_LOG_PATTERN, line)
                if not match: continue
                ip, ts, method, url, status, ua = match.group('ip'), self._parse_timestamp(match.group('timestamp')), match.group('method'), match.group('url'), match.group('status'), match.group('user_agent')
                requests.append({'ip': ip, 'timestamp': ts, 'status': status, 'url': url, 'ua': ua})
                # Detection patterns
                url_up = url.upper()
                if any(p in url_up for p in ["UNION SELECT", "OR '1'='1", "OR 1=1", "DROP TABLE", "--", "SLEEP(", "BENCHMARK("]):
                    report.findings.append(Finding(Severity.MEDIUM, "SQL_injection", ts, ip, f"SQLi attempt in URL", url=url))
                
                if any(p in url_up for p in ["<SCRIPT", "ALERT(", "ONERROR=", "ONLOAD="]):
                    report.findings.append(Finding(Severity.MEDIUM, "XSS_attempt", ts, ip, f"XSS attempt in URL", url=url))

                if any(p in url_up for p in ["../..", "/ETC/PASSWD", "/ETC/SHADOW", "WINDOWS/SYSTEM32", "CONFIG/SAM"]):
                    severity = Severity.HIGH if any(x in url_up for x in ["PASSWD", "SHADOW", "SAM"]) else Severity.MEDIUM
                    report.findings.append(Finding(severity, "dir_traversal", ts, ip, f"Traversal attempt", url=url))

                if any(p in ua.lower() for p in ["sqlmap", "nikto", "masscan", "nmap", "zgrab"]):
                    report.findings.append(Finding(Severity.LOW, "scanner_agent", ts, ip, f"Agent: {ua}"))

        ip_404s = {}
        for r in requests:
            if r['status'] == '404':
                ip_404s[r['ip']] = ip_404s.get(r['ip'], []) + [r['timestamp']]
        for ip, tss in ip_404s.items():
            if len(tss) >= 20:
                report.findings.append(Finding(Severity.MEDIUM, "404_flood", tss[-1], ip, f"{len(tss)} errors in short time"))
        report.generate_summary()
        return report
