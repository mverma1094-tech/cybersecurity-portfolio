# Incident Report IR-2026-001: SSH Brute Force and Unauthorized Login

> **Simulated incident** written for practice. All IPs are from reserved documentation ranges. The evidence matches the sample data in `packet_analysis/` and the log analysis in my QA portfolio.

| Field | Detail |
|---|---|
| **Severity** | High |
| **Status** | Closed |
| **Affected host** | web01 (10.0.0.10), public web server |
| **Attacker IP** | 203.0.113.45 |
| **Framework** | NIST SP 800-61 incident handling lifecycle |

---

## 1. Summary
An external IP scanned web01 for open ports, then ran a password-guessing attack against SSH. After 6 failed attempts, the attacker logged in successfully as `admin`. The account was disabled and the IP blocked within 40 minutes of the successful login. No evidence of data theft was found.

## 2. Timeline (Oct 18)

| Time | Event | Source |
|---|---|---|
| 08:10 | SYN scan of 25 ports on web01 from 203.0.113.45 | Packet capture |
| 08:15–08:15:50 | 6 failed SSH logins (root, then invalid user `test`) | /var/log/auth.log |
| 13:20 | **Successful SSH login as `admin`** from 203.0.113.45 | /var/log/auth.log |
| 13:24 | Splunk alert fires: success after brute force | SIEM |
| 13:35 | Analyst confirms alert is a true positive | Triage |
| 13:42 | `admin` account locked, active session killed | Containment |
| 14:00 | 203.0.113.45 blocked at the firewall | Containment |

## 3. Detection and Analysis
- **How it was found:** The Splunk rule "Successful login after brute force" (see `splunk_detections/`) matched a success from an IP with 5+ prior failures.
- **Why it's a true positive:** The IP is external, it scanned ports first, it guessed common usernames, and `admin` does not normally log in from outside the network.
- **What the attacker did after login:** Shell history showed `whoami`, `uname -a`, and `cat /etc/passwd` (reconnaissance only). No new files, cron jobs, or user accounts were found.

### MITRE ATT&CK Mapping
| Tactic | Technique | Evidence |
|---|---|---|
| Reconnaissance / Discovery | T1046 Network Service Discovery | 25-port SYN scan |
| Credential Access | T1110.001 Brute Force: Password Guessing | Repeated failed SSH logins |
| Initial Access | T1078 Valid Accounts | Successful login as `admin` |
| Lateral Movement | T1021.004 Remote Services: SSH | Remote shell over SSH |
| Discovery | T1082 System Information Discovery | `uname -a`, `whoami` |

## 4. Containment, Eradication, and Recovery
1. Locked the `admin` account and ended its SSH session
2. Blocked 203.0.113.45 at the perimeter firewall
3. Reset passwords for all accounts on web01
4. Checked for persistence (cron, `authorized_keys`, new users, services): none found
5. Returned web01 to service after the checks came back clean

## 5. Root Cause
- SSH was open to the internet with **password login allowed**
- The `admin` account had a **weak password**
- **No account lockout** after repeated failures

## 6. Lessons Learned and Recommendations
| # | Recommendation | Priority |
|---|---|---|
| 1 | Turn off SSH password login; require SSH keys | High |
| 2 | Restrict SSH to the VPN or an allowlist of IPs | High |
| 3 | Add fail2ban or account lockout after 5 failures | High |
| 4 | Enforce MFA for all admin accounts | Medium |
| 5 | Lower alert threshold for logins on public servers | Medium |
