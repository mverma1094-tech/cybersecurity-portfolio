# Splunk Detection Rules (SPL)

Detection searches for common attacks, each mapped to MITRE ATT&CK.
Index and sourcetype names (`linux`, `linux_secure`, `firewall`, `wineventlog`, `dns`) are examples; change them to match your environment.

---

## 1. SSH Brute Force
**MITRE:** T1110.001 Brute Force: Password Guessing
**Logic:** 5 or more failed SSH logins from one IP within 10 minutes.

```spl
index=linux sourcetype=linux_secure "Failed password"
| rex "from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| bin _time span=10m
| stats count AS failures, dc(user) AS users_tried BY _time, src_ip, host
| where failures >= 5
| sort - failures
```
**Tuning:** Exclude known scanners or admin jump boxes with `NOT src_ip IN (...)`.

---

## 2. Successful Login After Brute Force
**MITRE:** T1078 Valid Accounts
**Logic:** An IP with 5+ failures that later logs in successfully. This is the alert that caught IR-2026-001.

```spl
index=linux sourcetype=linux_secure ("Failed password" OR "Accepted password")
| rex "for (invalid user )?(?<user>\S+) from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| eval outcome=if(searchmatch("Accepted password"), "success", "failure")
| stats count(eval(outcome="failure")) AS failures,
        count(eval(outcome="success")) AS successes,
        values(user) AS users BY src_ip
| where failures >= 5 AND successes > 0
```

---

## 3. Port Scan
**MITRE:** T1046 Network Service Discovery
**Logic:** One source touches 15+ different ports on one host within 5 minutes.

```spl
index=network sourcetype=firewall
| bin _time span=5m
| stats dc(dest_port) AS unique_ports, values(action) AS actions BY _time, src_ip, dest_ip
| where unique_ports >= 15
```

---

## 4. User Added to Local Administrators (Windows)
**MITRE:** T1098 Account Manipulation
**Logic:** Event ID 4732 = a member was added to a security-enabled local group.

```spl
index=wineventlog EventCode=4732 Group_Name="Administrators"
| table _time, host, src_user, member_name, Group_Name
```

---

## 5. Suspicious DNS Lookups
**MITRE:** T1071.004 Application Layer Protocol: DNS
**Logic:** Very long subdomains or risky top-level domains, often seen with malware or DNS tunneling.

```spl
index=dns
| eval subdomain=mvindex(split(query, "."), 0)
| eval sub_len=len(subdomain)
| where sub_len >= 12 OR match(query, "\.(xyz|top|zip|click)$")
| stats count BY src_ip, query
| sort - count
```

---

## Alert Triage Checklist
1. **Who:** Is the source IP internal or external? Known or new?
2. **What:** Which account or host? Is it privileged?
3. **When:** Normal business hours for this user?
4. **Context:** Any related alerts from the same IP or user in the last 24 hours?
5. **Decide:** True positive → escalate and contain. False positive → document why and tune the rule.
