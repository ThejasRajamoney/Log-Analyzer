from colorama import init, Fore, Back, Style
from analyzer.base_analyzer import Report, Severity

init(autoreset=True)

class TerminalReporter:
    def __init__(self, min_severity: str = "INFO"):
        self.min_sev = {"INFO":0, "LOW":1, "MEDIUM":2, "HIGH":3, "CRITICAL":4}.get(min_severity, 0)
    
    def print_report(self, r: Report):
        print("\n" + Fore.CYAN + "="*50)
        print(f" REPORT: {r.log_type.upper()} - {r.log_file}")
        print(Fore.CYAN + "="*50)
        for f in r.findings:
            if {"INFO":0, "LOW":1, "MEDIUM":2, "HIGH":3, "CRITICAL":4}.get(f.severity.value) < self.min_sev: continue
            col = {Severity.CRITICAL: Back.RED+Fore.WHITE, Severity.HIGH: Fore.RED, Severity.MEDIUM: Fore.YELLOW, Severity.LOW: Fore.CYAN}.get(f.severity, Fore.WHITE)
            ip_str = str(f.ip) if f.ip is not None else "N/A"
            type_str = str(f.type)
            print(f"[{col}{f.severity.value}{Style.RESET_ALL}] {type_str:15} | IP: {ip_str:15} | {f.details}")

        print("-"*50)
        s = r.summary
        print(f"Summary: Suspicious: {s.get('total_suspicious')} | Critical: {s.get('critical')} | High: {s.get('high')}")
