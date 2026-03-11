from datetime import timedelta

def detect_brute_force(attempts, threshold):
    """Generic brute force detector."""
    ip_failed = {}
    for fa in attempts:
        ip_failed[fa['ip']] = ip_failed.get(fa['ip'], []) + [fa['timestamp']]
    
    findings = []
    for ip, tss in ip_failed.items():
        if len(tss) >= threshold:
            findings.append({
                "ip": ip,
                "timestamp": tss[-1],
                "count": len(tss)
            })
    return findings
