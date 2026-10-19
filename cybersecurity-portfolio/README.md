# Cybersecurity Portfolio

Hands-on security projects covering **network traffic analysis, vulnerability management, incident response, SIEM detection, and risk assessment**.

**Tools and frameworks:** Python, Scapy, Wireshark (PCAP), Splunk SPL, Nessus-style scan data, PyTest, MITRE ATT&CK, NIST CSF, NIST SP 800-61

All data in this repo is sample data. IPs come from reserved documentation ranges, and the business in the risk assessment is fictional.

---

## Projects

### 1. PCAP Traffic Analyzer — `packet_analysis/`
Python tool that reads packet captures (the same `.pcap` files Wireshark opens) and flags suspicious activity.
- Detects **port scans**, **passwords sent over unencrypted HTTP**, and **suspicious DNS lookups**
- Reports top talkers by packet count and masks any credentials it finds
- `generate_sample_pcap.py` builds a test capture with 3 planted attacks
- **11 PyTest tests**, including boundary tests on the scan threshold (14 ports = no alert, 15 = alert)

### 2. Vulnerability Prioritizer — `vulnerability_prioritization/`
Ranks vulnerability scan findings by real-world risk, not just CVSS score.
- Combines a Nessus-style CSV export with an asset inventory (criticality, internet exposure)
- Removes duplicate findings and assigns fix-by deadlines (P1 = 7 days through P4 = 180 days)
- Shows why context matters: the same CVSS 8.1 flaw ranks higher on a public web server than on an internal PC
- **15 PyTest tests**

### 3. Incident Response Report — `incident_response/`
Full write-up of a simulated SSH brute-force attack that led to an unauthorized login.
- Follows the **NIST SP 800-61** lifecycle: detection, analysis, containment, eradication, recovery, lessons learned
- Includes a timeline, root cause, and **MITRE ATT&CK** technique mapping

### 4. Splunk Detection Rules — `splunk_detections/`
**5 SPL detection searches**, each mapped to MITRE ATT&CK:
SSH brute force, successful login after brute force, port scans, users added to local admins, and suspicious DNS. Includes an alert triage checklist.

### 5. Risk Assessment — `risk_assessment/`
**NIST CSF** risk assessment for a fictional grocery store with POS terminals.
- Asset inventory, **risk register** (likelihood x impact), heat map, and controls audit
- PCI DSS considerations and top 3 prioritized recommendations

---

## How to Run

```bash
pip install -r requirements.txt

# Packet analysis
cd packet_analysis
python generate_sample_pcap.py
python pcap_analyzer.py sample.pcap
pytest -v

# Vulnerability prioritization
cd ../vulnerability_prioritization
python prioritize.py sample_scan_results.csv assets.csv
pytest -v
```

Tests also run automatically on every push through **GitHub Actions**.
