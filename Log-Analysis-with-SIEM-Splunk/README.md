# 🛡️ SOC Level 1 Lab Report: Practical Log Analysis

An investigative incident response and log analysis report completed as part of the **Practical TryHackMe SOC Analyst Portfolio** series. This documentation highlights hands-on experience in threat hunting, log parsing, Windows Sysmon event analysis, Linux authentication auditing, and web server log inspection using **Splunk SIEM**.

---

## 📋 Table of Contents
1. [Executive Summary](#executive-summary)
2. [Windows Endpoint & Log Analysis](#windows-endpoint--log-analysis)
3. [Linux Authentication & System Analysis](#linux-authentication--system-analysis)
4. [Web Server Log Analysis](#web-server-log-analysis)
5. [Conclusion & Key Takeaways](#conclusion--key-takeaways)

---

## 🔍 Executive Summary
During a simulated shift as an SOC Level 1 Analyst, multiple security alerts were triaged across Windows endpoints, Linux servers, and web application components. Analysis uncovered a multi-stage intrusion consisting of malicious Windows binary execution (`SharePoInt.exe`), persistence mechanisms via scheduled tasks (`Office365 Install`), a compromised Linux user account (`jack-brown`) with privilege escalation to `root`, unauthorized SSH user creation (`remote-ssh`), and a targeted WordPress brute-force attack executed via `WPScan`.

---

## 💻 Windows Endpoint & Log Analysis
Investigation of Windows Sysmon operational logs revealed execution of an unauthorized payload establishing an outbound network connection and persistence via the Windows Task Scheduler.

### **Key Findings & Answers:**
* **Connection Destination IP:** `10.10.114.80`
* **Malicious Process Image:** `C:\Windows\Temp\SharePoInt.exe` (PID: 1460)
* **Process MD5 Hash:** `770D14FFA142F09730B415506249E7D1`
* **Scheduled Task Persistence:** `Office365 Install`

### **Splunk Investigation Query & Evidence:**
```spl
DestinationPort=5678 
| table _time Image DestinationIp DestinationPort
Event Evidence: Sysmon EventCode 3 showed an outbound TCP connection from SharePoInt.exe to destination IP 10.10.114.80 on port 5678.

🐧 Linux Authentication & System Analysis
An in-depth review of Linux authentication and system logs uncovered brute-force activity, unauthorized user account creation, privilege escalation, and cron-based persistence.

Key Findings & Answers:
Timestamp of remote-ssh Account Creation: 2025-08-12 09:52:57

Privileged User: jack-brown

Source IP: 10.14.94.82

Failed Login Attempts: 4

Persistence Port: 7654

Splunk Investigation Queries & Evidence:
Account Creation Search: new user: "remote-ssh"

Failed Login Analysis: source="auth.log" process=sshd ("Failed password" OR "Invalid user" OR "authentication failure")

Cron Persistence: Discovered a Python reverse shell payload scheduled via cron executing every minute connecting back to port 7654.

🌐 Web Server Log Analysis
An alert regarding an anomalous surge in web traffic targeting the organization's server was investigated to determine the nature of the web-based attack vector.

Key Findings & Answers:
Target URI Path: /wp-login.php

Attacker Source IP: 10.10.243.134

Attack Classification: Brute Force

Tool Fingerprint (User-Agent): WPScan v3.8.28

Splunk Investigation Queries Used:
URI Path Ranking: | top limit=1 uri_path

IP Source Extraction: uri_path="/wp-login.php" | stats count by clientip | sort - count

Tool Identification: clientip="10.10.243.134" | stats count by useragent

📌 Conclusion & Key Takeaways
Multi-Platform Triage: Successfully correlated disparate telemetry sources (Windows Sysmon, Linux authentication/system logs, and Web access logs) to map out a complete adversary kill chain.

SIEM Proficiency: Demonstrated solid competency in using Splunk filtering, field extractions, statistical aggregations (stats count, top, table), and process tracking to resolve complex security incidents.