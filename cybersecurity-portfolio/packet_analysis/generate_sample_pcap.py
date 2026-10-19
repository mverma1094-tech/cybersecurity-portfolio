"""
Builds sample.pcap: a small capture with normal traffic plus three planted
suspicious events for the analyzer to find:
  1. A SYN port scan from 203.0.113.45 against 10.0.0.10
  2. A login sent over plain HTTP (password visible in cleartext)
  3. DNS lookups to a suspicious-looking domain

Usage:
    python generate_sample_pcap.py
"""
from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw, wrpcap

CLIENT = "10.0.0.25"
SERVER = "10.0.0.10"
SCANNER = "203.0.113.45"


def build_packets():
    packets = []

    # Normal HTTPS traffic
    for i in range(10):
        packets.append(IP(src=CLIENT, dst="93.184.216.34") / TCP(sport=50000 + i, dport=443, flags="PA"))

    # Normal DNS lookups
    for name in ["example.com", "github.com", "python.org"]:
        packets.append(IP(src=CLIENT, dst="8.8.8.8") / UDP(sport=53000, dport=53) / DNS(rd=1, qd=DNSQR(qname=name)))

    # 1. Port scan: one SYN to each of 25 different ports
    for port in range(20, 45):
        packets.append(IP(src=SCANNER, dst=SERVER) / TCP(sport=40000, dport=port, flags="S"))

    # 2. Cleartext HTTP login
    body = "username=jsmith&password=Summer2026!"
    http = (
        "POST /login HTTP/1.1\r\n"
        f"Host: {SERVER}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n\r\n{body}"
    )
    packets.append(IP(src=CLIENT, dst=SERVER) / TCP(sport=51000, dport=80, flags="PA") / Raw(load=http))

    # 3. Suspicious DNS: long random-looking subdomains (a common sign of malware or DNS tunneling)
    for sub in ["x7k2p9q4w8z1m3n6", "a9f3k1q7z2x8c4v5"]:
        packets.append(
            IP(src=CLIENT, dst="8.8.8.8") / UDP(sport=53001, dport=53)
            / DNS(rd=1, qd=DNSQR(qname=f"{sub}.badupdate-server.xyz"))
        )

    return packets


if __name__ == "__main__":
    wrpcap("sample.pcap", build_packets())
    print("Wrote sample.pcap")
