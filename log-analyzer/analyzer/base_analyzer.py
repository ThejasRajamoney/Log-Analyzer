from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

@dataclass
class Finding:
    severity: Severity
    type: str
    timestamp: datetime
    ip: str
    details: str
    targeted_user: Optional[str] = None
    url: Optional[str] = None
    recommendation: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "severity": self.severity.value,
            "type": self.type,
            "timestamp": self.timestamp.isoformat(),
            "ip": self.ip,
            "details": self.details,
            "targeted_user": self.targeted_user,
            "url": self.url,
            "recommendation": self.recommendation
        }

@dataclass
class Report:
    report_generated: datetime
    log_file: str
    log_type: str
    total_lines_analyzed: int
    findings: List[Finding] = field(default_factory=list)
    summary: Dict[str, int] = field(default_factory=dict)
    unique_ips: List[str] = field(default_factory=list)
    top_attacker_ips: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

    def generate_summary(self):
        self.summary = {
            "total_suspicious": len(self.findings),
            "critical": len([f for f in self.findings if f.severity == Severity.CRITICAL]),
            "high": len([f for f in self.findings if f.severity == Severity.HIGH]),
            "medium": len([f for f in self.findings if f.severity == Severity.MEDIUM]),
            "low": len([f for f in self.findings if f.severity == Severity.LOW]),
            "unique_ips": len(set(f.ip for f in self.findings if f.ip))
        }
        self.unique_ips = list(set(f.ip for f in self.findings if f.ip))
        ip_counts = {}
        for f in self.findings:
            if f.ip:
                ip_counts[f.ip] = ip_counts.get(f.ip, 0) + 1
        self.top_attacker_ips = sorted(ip_counts, key=ip_counts.get, reverse=True)[:5]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_generated": self.report_generated.isoformat(),
            "log_file": self.log_file,
            "log_type": self.log_type,
            "total_lines_analyzed": self.total_lines_analyzed,
            "summary": {
                "total_suspicious": self.summary.get("total_suspicious", 0),
                "unique_ips": self.summary.get("unique_ips", 0),
                "critical": self.summary.get("critical", 0),
                "high": self.summary.get("high", 0),
                "medium": self.summary.get("medium", 0),
                "low": self.summary.get("low", 0),
            },
            "findings": [f.to_dict() for f in self.findings],
            "top_attacker_ips": self.top_attacker_ips,
            "recommendations": self.recommendations
        }

class BaseAnalyzer(ABC):
    def __init__(self, file_path: str, threshold: int = 5):
        self.file_path = file_path
        self.threshold = threshold
        self.total_lines = 0
        self.findings = []

    @abstractmethod
    def analyze(self) -> Report:
        pass
