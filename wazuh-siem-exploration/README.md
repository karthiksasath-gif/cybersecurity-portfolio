# 🛡️ Exploring Wazuh: SIEM, XDR & Endpoint Security

## 📋 Project Overview
This project documents hands-on security monitoring, vulnerability assessment, and log analysis performed using the **Wazuh XDR and SIEM platform** as part of the TryHackMe cybersecurity training series. The lab explores deployment architecture, agent monitoring, configuration assessment, vulnerability management, custom log ingestion, and advanced detection features.

---

## 🛠️ Lab Tasks & Technical Breakdown

### **1. Wazuh Server & Agent Architecture**
* **Deployment Model:** Configured and navigated a centralized Wazuh management server communicating with distributed agents (`WIN-SERVER` and `linux-server`).
* **Agent Status & Specs:** Reviewed agent connection statuses and inspected system hardware telemetry (e.g., identifying the Windows agent CPU as *AMD EPYC 7571*).

### **2. IT Hygiene & Configuration Assessment (CIS Benchmarks)**
* **IT Hygiene:** Inspected system inventory, listening ports, local user privileges, and installed software packages. Identified custom third-party packages such as *Notepad++*.
* **CIS Benchmarks:** Executed automated security audits against compliance baselines (running hundreds of checks on Windows and evaluating the Linux agent's configuration score at *46%*).

### **3. Vulnerability Detection & CVE Analysis**
* **Software Auditing:** Scanned agent packages against known vulnerabilities to identify outdated applications and missing security patches.
* **Key Findings:** 
  * Windows Agent Notepad++ Vulnerability: `CVE-2026-25926`
  * Linux Server Earliest Critical Vulnerability: `CVE-2021-3773`

### **4. Logging, Reporting & Visualization**
* **Log Ingestion & Parsing:** Explored Wazuh's Discover module to filter raw logs and parse authentication events (`decoder.name: sshd`).
* **SIEM Threat Hunting:** Investigated Windows Defender security events using event query filters (`data.win.system.eventID: 1116`), successfully identifying malware threat signatures (`Trojan:Win32/CobaltStrike.PU!MTB`).
* **Dashboards:** Analyzed aggregated operational and security events totaling over 5,400+ entries across the platform dashboard.

### **5. Custom Log Collection, Decoders & Rules**
* **Agent Configuration:** Customized group-level policies to collect auxiliary telemetry sources, including Linux authentication logs (`/var/log/auth.log`) and Windows Sysmon operational events.
* **Detection Engineering:** Analyzed Wazuh **Decoders** (field extraction templates) and custom **Rules** (threshold severity levels 1 to 15, where level 15 represents maximum criticality).

### **6. Advanced Wazuh Features**
* **Active Response:** Evaluated automated remediation scripts and command execution triggers upon rule violation.
* **File Integrity Monitoring (FIM):** Reviewed mechanisms for tracking unauthorized modifications to critical system files, registry keys, and sensitive configuration profiles.
* **Threat Intelligence & Compliance:** Noted integrations for malware scanning (YARA/VirusTotal), cloud security telemetry (AWS, Azure, M365), OSquery integration, and automated mapping to compliance frameworks (MITRE ATT&CK, GDPR, PCI-DSS).

---

## 📌 Key Takeaways & Skills Demonstrated
* **Unified XDR Management:** Proficiency in deploying, managing, and navigating a centralized Wazuh SIEM/XDR infrastructure.
* **Endpoint Hardening & Auditing:** Experience utilizing IT hygiene and CIS compliance benchmarks to identify host misconfigurations.
* **Threat Detection & Parsing:** Understanding of log ingestion lifecycles, decoders, rule logic, and critical severity prioritization.