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
During a simulated shift as an SOC Level 1 Analyst, multiple security alerts were triaged across Windows endpoints, Linux servers, and web application components. Analysis uncovered a multi-stage intrusion consisting of malicious Windows binary execution (`SharePoInt.exe`), persistence mechanisms via scheduled tasks (`Office365 Install`)[cite: 1, 2, 3], a compromised Linux user account (`jack-brown`) with privilege escalation to `root`, unauthorized SSH user creation (`remote-ssh`)[cite: 4, 5, 6], and a targeted WordPress brute-force attack executed via `WPScan`.

---

## 💻 Windows Endpoint & Log Analysis
Investigation of Windows Sysmon operational logs revealed execution of an unauthorized payload establishing an outbound network connection and persistence via the Windows Task Scheduler.

### **Key Findings & Answers:**
* **Connection Destination IP:** `10.10.114.80`[cite: 1, 2]
* **Malicious Process Image:** `C:\Windows\Temp\SharePoInt.exe` (PID: 1460)[cite: 1, 2]
* **Process MD5 Hash:** `770D14FFA142F09730B415506249E7D1`[cite: 3]
* **Scheduled Task Persistence:** `Office365 Install`

### **Splunk Investigation Query & Evidence:**
```spl
DestinationPort=5678 
| table _time Image DestinationIp DestinationPort