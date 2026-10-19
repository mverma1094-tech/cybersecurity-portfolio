"""
PCAP analyzer: reads a packet capture (the same files Wireshark opens)
and reports traffic stats and suspicious activity.

Checks:
  - Top talkers (which IPs send the most packets)
  - Port scans (one source sending SYNs to many ports on one host)
  - Cleartext credentials in HTTP traffic
  - Suspicious DNS lookups (long random-looking names, risky TLDs)

Usage:
    python pcap_analyzer.py sample.pcap
"""
import re
import sys
from collections import Counter, defaultdict

from scapy.all import rdpcap, IP, TCP, DNSQR, Raw

PORT_SCAN_THRESHOLD = 15          # distinct ports from one source to one host
RISKY_TLDS = (".xyz", ".top", ".zip", ".click")
CREDENTIAL_PATTERN = re.compile(r"(pass(word)?|pwd)=([^&\s]+)", re.IGNORECASE)


def top_talkers(packets, n=3):
    counts = Counter(p[IP].src for p in packets if IP in p)
    return counts.most_common(n)


def find_port_scans(packets, threshold=PORT_SCAN_THRESHOLD):
    ports_hit = defaultdict(set)
    for p in packets:
        if IP in p and TCP in p and p[TCP].flags == "S":
            ports_hit[(p[IP].src, p[IP].dst)].add(p[TCP].dport)
    return [
        {"src": src, "dst": dst, "ports": len(ports)}
        for (src, dst), ports in ports_hit.items()
        if len(ports) >= threshold
    ]


def find_cleartext_credentials(packets):
    findings = []
    for p in packets:
        if TCP in p and p[TCP].dport == 80 and Raw in p:
            payload = p[Raw].load.decode(errors="ignore")
            match = CREDENTIAL_PATTERN.search(payload)
            if match:
                # Mask the password in the report so the tool doesn't leak it again
                findings.append({"src": p[IP].src, "dst": p[IP].dst, "field": match.group(1), "value": "****"})
    return findings


def is_suspicious_domain(name):
    name = name.rstrip(".").lower()
    first_label = name.split(".")[0]
    random_looking = len(first_label) >= 12 and sum(c.isdigit() for c in first_label) >= 3
    return random_looking or name.endswith(RISKY_TLDS)


def find_suspicious_dns(packets):
    found = []
    for p in packets:
        if DNSQR in p:
            name = p[DNSQR].qname.decode(errors="ignore").rstrip(".")
            if is_suspicious_domain(name) and name not in found:
                found.append(name)
    return found


def analyze(path):
    packets = rdpcap(path)
    return {
        "total_packets": len(packets),
        "top_talkers": top_talkers(packets),
        "port_scans": find_port_scans(packets),
        "cleartext_credentials": find_cleartext_credentials(packets),
        "suspicious_dns": find_suspicious_dns(packets),
    }


def print_report(r):
    print(f"Total packets: {r['total_packets']}\n")
    print("Top talkers:")
    for ip, count in r["top_talkers"]:
        print(f"  {ip:<16} {count} packets")
    print("\nPort scans:")
    for s in r["port_scans"] or [None]:
        print(f"  [HIGH] {s['src']} scanned {s['ports']} ports on {s['dst']}" if s else "  none")
    print("\nCleartext credentials:")
    for c in r["cleartext_credentials"] or [None]:
        print(f"  [HIGH] {c['src']} -> {c['dst']} sent '{c['field']}' over HTTP" if c else "  none")
    print("\nSuspicious DNS lookups:")
    for d in r["suspicious_dns"] or [None]:
        print(f"  [MEDIUM] {d}" if d else "  none")


if __name__ == "__main__":
    print_report(analyze(sys.argv[1] if len(sys.argv) > 1 else "sample.pcap"))
