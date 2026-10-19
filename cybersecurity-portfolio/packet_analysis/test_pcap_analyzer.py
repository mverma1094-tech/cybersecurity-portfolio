import pytest
from scapy.all import IP, TCP, wrpcap

from generate_sample_pcap import build_packets, SCANNER, SERVER, CLIENT
from pcap_analyzer import analyze, find_port_scans, is_suspicious_domain


@pytest.fixture(scope="module")
def report(tmp_path_factory):
    path = tmp_path_factory.mktemp("pcap") / "sample.pcap"
    wrpcap(str(path), build_packets())
    return analyze(str(path))


def test_counts_all_packets(report):
    assert report["total_packets"] == 41


def test_scanner_is_top_talker(report):
    assert report["top_talkers"][0] == (SCANNER, 25)


def test_detects_port_scan(report):
    assert report["port_scans"] == [{"src": SCANNER, "dst": SERVER, "ports": 25}]


def test_detects_cleartext_password_and_masks_it(report):
    creds = report["cleartext_credentials"]
    assert len(creds) == 1
    assert creds[0]["src"] == CLIENT
    assert creds[0]["value"] == "****"


def test_flags_only_suspicious_domains(report):
    assert report["suspicious_dns"] == [
        "x7k2p9q4w8z1m3n6.badupdate-server.xyz",
        "a9f3k1q7z2x8c4v5.badupdate-server.xyz",
    ]


# Boundary value analysis on the port-scan threshold (15)
def syns(n):
    return [IP(src="192.0.2.9", dst=SERVER) / TCP(dport=1000 + i, flags="S") for i in range(n)]


def test_14_ports_not_a_scan():
    assert find_port_scans(syns(14)) == []


def test_15_ports_is_a_scan():
    assert find_port_scans(syns(15))[0]["ports"] == 15


@pytest.mark.parametrize("domain, expected", [
    ("github.com", False),
    ("mail.google.com", False),
    ("x7k2p9q4w8z1m3n6.example.com", True),
    ("free-prize.click", True),
])
def test_domain_rules(domain, expected):
    assert is_suspicious_domain(domain) is expected
