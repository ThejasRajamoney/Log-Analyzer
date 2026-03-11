import json
import os
from datetime import datetime
from .base_analyzer import BaseAnalyzer, Report, Finding, Severity

class WindowsAnalyzer(BaseAnalyzer):
    def analyze(self) -> Report:
        report = Report(datetime.now(), self.file_path, "windows", 0)
        if not os.path.exists(self.file_path): return report
        with open(self.file_path, 'r') as f: 
            try:
                events = json.load(f)
            except:
                return report
        
        new_users = []
        for event in events:
            report.total_lines_analyzed += 1
            eid, ip, user = event.get('EventID'), event.get('IpAddress', 'N/A'), event.get('TargetUserName', 'N/A')
            ts_str = event.get('TimeCreated')
            # Handle potential variation in timestamp format
            try:
                ts = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
            except:
                ts = datetime.now()
                
            if eid == 4625:
                report.findings.append(Finding(Severity.MEDIUM, "failed_logon", ts, ip, f"Failed for {user}", user))
            elif eid == 4720:
                new_users.append({'ts': ts, 'user': user})
                report.findings.append(Finding(Severity.MEDIUM, "user_created", ts, ip, f"Created: {user}", user))
            elif eid == 4732:
                report.findings.append(Finding(Severity.HIGH, "privilege_added", ts, ip, f"Admin group for {user}", user))
                # Sequence detection
                for nu in new_users:
                    if nu['user'] == user and (ts - nu['ts']).total_seconds() < 300:
                        report.findings.append(Finding(Severity.CRITICAL, "new_privileged_user", ts, ip, f"User {user} created and promoted quickly", user))
            elif eid == 7045:
                report.findings.append(Finding(Severity.HIGH, "service_installed", ts, ip, f"Svc: {event.get('ServiceName')}"))
        report.generate_summary()
        return report
