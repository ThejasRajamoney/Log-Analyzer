import argparse
import sys
import os
from analyzer.ssh_analyzer import SSHAnalyzer
from analyzer.web_analyzer import WebAnalyzer
from analyzer.windows_analyzer import WindowsAnalyzer
from reporter.terminal_report import TerminalReporter
from reporter.json_report import JSONReporter

def main():
    parser = argparse.ArgumentParser(description='Log Analyzer for Suspicious Activity')
    parser.add_argument('--type', choices=['ssh', 'web', 'windows', 'all'], required=True)
    parser.add_argument('--dir', type=str, help='Directory containing log files')
    parser.add_argument('--file', type=str, help='Single log file to analyze')
    parser.add_argument('--severity', type=str, default='LOW', choices=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])
    parser.add_argument('--output', type=str, help='Save JSON report to file')
    parser.add_argument('--threshold', type=int, default=5)
    args = parser.parse_args()

    FILE_MAP = {
        'ssh':     'auth.log',
        'web':     'access.log',
        'windows': 'windows.evtx.json'
    }

    ANALYZER_MAP = {
        'ssh':     SSHAnalyzer,
        'web':     WebAnalyzer,
        'windows': WindowsAnalyzer
    }

    types = ['ssh', 'web', 'windows'] if args.type == 'all' else [args.type]

    reports = []
    for t in types:
        cls = ANALYZER_MAP[t]
        if args.file:
            file_path = args.file
        elif args.dir:
            file_path = os.path.join(args.dir, FILE_MAP[t])
        else:
            print(f"[ERROR] Provide --file or --dir")
            continue
        reports.append(cls(file_path, args.threshold).analyze())

    reporter = TerminalReporter(min_severity=args.severity)
    for report in reports:
        reporter.print_report(report)

    if args.output:
        json_reporter = JSONReporter()
        json_reporter.save(reports, args.output)
        print(f"Saved: {args.output}")

if __name__ == "__main__":
    main()
