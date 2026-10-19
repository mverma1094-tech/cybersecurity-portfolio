# Security Risk Assessment: Corner Street Market

> **Fictional business** created for practice. Framework: **NIST Cybersecurity Framework (CSF) 2.0**.

## Scope
Corner Street Market is a small grocery store with 2 locations and 25 employees.

| Asset | Description | Criticality |
|---|---|---|
| POS terminals (6) | Card payments, connected to store Wi-Fi | High |
| Back-office PC | Inventory, payroll, email | High |
| Online ordering site | Hosted website with customer accounts | High |
| Store Wi-Fi | One network shared by POS, staff, and guests | Medium |
| Security cameras | Network cameras, default settings | Low |

---

## Risk Register

**Likelihood** and **Impact** are rated 1 (low) to 5 (high). **Risk score = Likelihood x Impact.**

| ID | Risk | Likelihood | Impact | Score | CSF Function | Recommended Control |
|---|---|:-:|:-:|:-:|---|---|
| R1 | POS terminals share Wi-Fi with guests; an attacker on guest Wi-Fi could reach card systems | 4 | 5 | **20** | Protect | Separate networks (VLANs) for POS, staff, and guests |
| R2 | Staff share one login on the back-office PC | 5 | 4 | **20** | Protect | Individual accounts, MFA on email and payroll |
| R3 | Phishing email leads to stolen credentials or malware | 4 | 4 | **16** | Protect | Phishing training, email filtering, MFA |
| R4 | No tested backups of inventory and payroll data | 3 | 5 | **15** | Recover | Daily automatic backups, one copy offline, test restores quarterly |
| R5 | Website software not regularly updated | 3 | 4 | **12** | Identify | Monthly patching and vulnerability scans |
| R6 | No logging or alerts for failed logins | 3 | 3 | **9** | Detect | Central logging with alerts on repeated failures |
| R7 | Cameras use default passwords | 3 | 2 | **6** | Protect | Change defaults, move cameras to their own network |

### Risk Heat Map
| Likelihood \ Impact | 2 | 3 | 4 | 5 |
|---|---|---|---|---|
| **5** | | | R2 | |
| **4** | | | R3 | R1 |
| **3** | R7 | R6 | R5 | R4 |

---

## Controls Assessment

| Control | In Place? | Notes |
|---|:-:|---|
| Least privilege (individual accounts) | No | Shared login on back-office PC |
| Multi-factor authentication | No | |
| Network segmentation | No | POS and guest Wi-Fi share one network |
| Antivirus / endpoint protection | Yes | On back-office PC only |
| Firewall | Yes | Router firewall, default rules |
| Encrypted card data | Yes | Handled by payment processor |
| Backups | Partial | Manual, untested |
| Password policy | No | |
| Security awareness training | No | |
| Incident response plan | No | |

## Compliance Note
Because the store takes card payments, it must follow **PCI DSS**. R1 (POS on a shared network) and R2 (shared logins) are both likely PCI DSS findings and should be fixed first.

## Top 3 Recommendations
1. **Segment the network:** POS terminals on their own isolated network (fixes R1, supports PCI DSS)
2. **Individual accounts + MFA** for email, payroll, and the website admin panel (fixes R2, R3)
3. **Automatic, tested backups** with one offline copy to recover from ransomware (fixes R4)
