# 🛡️ Log Analysis with SIEM (Splunk)

**Lab Environment:** TryHackMe — Practical SOC Analyst series

An incident response and log analysis investigation covering threat hunting, log parsing, Windows Sysmon event analysis, Linux authentication auditing, and web server log inspection using **Splunk SIEM**.

---

## 📋 Table of Contents

1. [Executive Summary](#executive-summary)
2. [Windows Endpoint & Log Analysis](#windows-endpoint--log-analysis)
3. [Linux Authentication & System Analysis](#linux-authentication--system-analysis)
4. [Web Server Log Analysis](#web-server-log-analysis)
5. [Conclusion & Key Takeaways](#conclusion--key-takeaways)

---

## 🔍 Executive Summary

During a simulated shift as an SOC Level 1 Analyst, multiple security alerts were triaged across Windows endpoints, Linux servers, and web application components. Analysis uncovered a multi-stage intrusion consisting of malicious Windows binary execution (`SharePoInt.exe`), persistence via scheduled tasks (`Office365 Install`), a compromised Linux user account (`jack-brown`) with privilege escalation to `root`, unauthorized SSH user creation (`remote-ssh`), and a targeted WordPress brute-force attack executed via `WPScan`.

| Finding | Severity |
| :--- | :--- |
| Windows malicious binary + scheduled task persistence | **High** |
| Linux privilege escalation to root + reverse-shell persistence | **Critical** |
| WordPress brute-force (WPScan) | **Medium** |

---

## 💻 Windows Endpoint & Log Analysis

**Severity: High**

Investigation of Windows Sysmon operational logs revealed execution of an unauthorized payload establishing an outbound network connection and persistence via the Windows Task Scheduler.

### Investigation Findings
* **Connection Destination IP:** `10.10.114.80`
* **Malicious Process Image:** `C:\Windows\Temp\SharePoInt.exe` (PID: 1460)
* **Process MD5 Hash:** `770D14FFA142F09730B415506249E7D1`
* **Scheduled Task Persistence:** `Office365 Install`

### Splunk Investigation Query & Evidence
```spl
DestinationPort=5678
| table _time Image DestinationIp DestinationPort
```
**Event Evidence:** Sysmon EventCode 3 showed an outbound TCP connection from `SharePoInt.exe` to destination IP `10.10.114.80` on port `5678`.

![Sysmon network connection — Splunk search results](screenshots/Windows%20logs/1.png)
![Scheduled task persistence evidence](screenshots/Windows%20logs/2.png)

### Recommended Actions
1. Isolate the affected host from the network immediately.
2. Kill process `SharePoInt.exe` (PID 1460) and delete the binary from `C:\Windows\Temp\`.
3. Remove the malicious scheduled task `Office365 Install`.
4. Block outbound traffic to `10.10.114.80:5678` at the firewall/proxy.
5. Submit the MD5 hash `770D14FFA142F09730B415506249E7D1` to threat intel (VirusTotal) to confirm classification and check for related IOCs.

---

## 🐧 Linux Authentication & System Analysis

**Severity: Critical**

Review of Linux authentication and system logs uncovered brute-force activity, unauthorized user account creation, privilege escalation, and cron-based persistence.

### Investigation Findings
* **Timestamp of remote-ssh Account Creation:** `2025-08-12 09:52:57`
* **Privileged User:** `jack-brown`
* **Source IP:** `10.14.94.82`
* **Failed Login Attempts:** `4`
* **Persistence Port:** `7654`

### Splunk Investigation Queries & Evidence
* **Account Creation Search:** `new user: "remote-ssh"`
* **Failed Login Analysis:**
```spl
source="auth.log" process=sshd ("Failed password" OR "Invalid user" OR "authentication failure")
```
* **Cron Persistence:** A Python reverse-shell payload was found scheduled via cron, executing every minute and connecting back to port `7654`.

![Failed SSH login attempts — auth.log](screenshots/Linux%20logs/4.png)
![Unauthorized remote-ssh account creation](screenshots/Linux%20logs/5.png)
![Cron reverse-shell persistence](screenshots/Linux%20logs/6.png)

### Recommended Actions
1. Disable the unauthorized `remote-ssh` account immediately.
2. Remove the malicious cron entry and the reverse-shell payload from disk.
3. Rotate credentials for `jack-brown` and review all actions taken under that account since compromise.
4. Block outbound connections to port `7654` at the host and network firewall.
5. Audit `/etc/sudoers` and group memberships for any other unauthorized privilege grants.
6. Rate-limit or geo-block repeated SSH failures from `10.14.94.82`; consider fail2ban if not already in place.

---

## 🌐 Web Server Log Analysis

**Severity: Medium**

An alert regarding an anomalous surge in web traffic targeting the organization's server was investigated to determine the nature of the web-based attack vector.

### Investigation Findings
* **Target URI Path:** `/wp-login.php`
* **Attacker Source IP:** `10.10.243.134`
* **Attack Classification:** Brute Force
* **Tool Fingerprint (User-Agent):** `WPScan v3.8.28`

### Splunk Investigation Queries Used
* **URI Path Ranking:**
```spl
| top limit=1 uri_path
```
* **IP Source Extraction:**
```spl
uri_path="/wp-login.php" | stats count by clientip | sort - count
```
* **Tool Identification:**
```spl
clientip="10.10.243.134" | stats count by useragent
```

![WPScan brute-force traffic pattern](screenshots/Web%20application%20logs/9.png)
![Attacker source IP and user-agent identification](screenshots/Web%20application%20logs/10.png)

### Recommended Actions
1. Block source IP `10.10.243.134` at the WAF/firewall.
2. Enforce a login rate-limit or CAPTCHA on `/wp-login.php`.
3. Confirm no successful authentication occurred during the attack window; force password resets if any did.
4. Enable 2FA on all WordPress admin accounts going forward.
5. Add `WPScan` and similar scanner user-agents to a WAF blocklist/alert rule.

---

## 📌 Conclusion & Key Takeaways

* **Multi-Platform Triage:** Correlated disparate telemetry sources (Windows Sysmon, Linux authentication/system logs, and web access logs) to map a complete adversary kill chain.
* **SIEM Proficiency:** Demonstrated competency in Splunk filtering, field extractions, statistical aggregations (`stats count`, `top`, `table`), and process tracking to resolve security incidents.
* **Prioritization:** Classified findings by severity (Critical → High → Medium) to reflect real-world triage order — the Linux root-level compromise was treated as the most urgent due to active persistence and escalated privileges.
