def detect_404_flood(requests, threshold=20):
    """Detects 404 flooding."""
    ip_404s = {}
    for r in requests:
        if r['status'] == '404':
            ip_404s[r['ip']] = ip_404s.get(r['ip'], []) + [r['timestamp']]
    
    findings = []
    for ip, tss in ip_404s.items():
        if len(tss) >= threshold:
            findings.append({"ip": ip, "timestamp": tss[-1], "count": len(tss)})
    return findings
