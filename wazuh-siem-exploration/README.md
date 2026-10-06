# 🛡️ Wazuh SIEM & XDR Platform Exploration

**Lab Environment:** TryHackMe — Wazuh: The Big Picture room

## 📋 Project Overview
Hands-on deployment, configuration, and investigation using the **Wazuh unified XDR/SIEM platform** — covering manager-agent architecture, CIS compliance benchmarking, vulnerability detection, log ingestion/parsing, and custom detection engineering (decoders and rules). Unlike my alert-triage projects, this one focuses on the **platform/engineering side** of SOC work: configuring the tool an analyst relies on, not just working tickets inside it.

---

## 🛠️ Lab Tasks & Technical Breakdown

### 1. Wazuh Server & Agent Architecture
* **Deployment Model:** Configured and navigated a centralized Wazuh management server communicating with distributed agents (`WIN-SERVER` and `linux-server`).
* **Agent Inspection:** Reviewed agent connection status and hardware telemetry (Windows agent CPU identified as `AMD EPYC 7571`).

![Agent architecture and status overview](screenshots/Wazuh%20agent%20groups/1.png)
![Agent groups and policy structure](screenshots/Wazuh%20agent%20groups/2.png)

### 2. IT Hygiene & Configuration Assessment (CIS Benchmarks)
* **IT Hygiene:** Inspected system inventory, listening ports, local user privileges, and installed software. Identified installed third-party software (e.g. Notepad++) via the Software > Packages view.
* **CIS Benchmark Auditing:** Ran automated compliance checks against CIS baselines — 347 checks on the Windows agent; Linux agent scored **46%** compliance.

![CIS Benchmark results — Linux agent](screenshots/Configuration%20Assessment/4.png)
![IT Hygiene — installed software inventory](screenshots/Configuration%20Assessment/5.png)

### 3. Vulnerability Detection & CVE Analysis

| Host | Finding | Identifier |
| :--- | :--- | :--- |
| Windows Agent | Most recent Notepad++ vulnerability | `CVE-2026-25926` |
| Linux Agent | Earliest critical vulnerability | `CVE-2021-3773` |

* Scanned agent-installed packages against known CVE databases to surface outdated/vulnerable software requiring patching.

![Vulnerability detection — CVE findings](screenshots/Vulnerability%20Detection/8.png)

### 4. Logging, Reporting & Threat Hunting
* **Log Parsing:** Used Wazuh's Discover module to filter raw authentication events (`decoder.name: sshd`).
* **Threat Hunting:** Queried Windows Defender events (`data.win.system.eventID: 1116`) and identified an actual malware signature: `Trojan:Win32/CobaltStrike.PU!MTB` — a Cobalt Strike beacon detection, notable because Cobalt Strike is a real-world post-exploitation/C2 framework commonly abused in ransomware intrusions.
* **Dashboard Analysis:** Reviewed the Demo Dashboard, aggregating **5,495 total events** across the environment.

![SIEM dashboard — aggregated event view](screenshots/Logging%20and%20Reporting/11.png)
![Cobalt Strike detection via Defender event query](screenshots/Logging%20and%20Reporting/12.png)

### 5. Custom Log Collection, Decoders & Detection Rules
* **Custom Ingestion:** Configured group-level agent policies to collect non-default log sources — Linux `/var/log/auth.log` and Windows Sysmon operational events.
* **Decoders:** Studied how Wazuh decoders extract structured fields (e.g. image path, command line, hash) from raw Sysmon event text via regex-based parsing.
* **Detection Rules Authored/Reviewed:** Analyzed a two-stage rule chain for PowerShell execution detection — a low-severity base rule flags all Sysmon Event ID 1 (process creation) logs, while a second, higher-severity rule (level 12) fires specifically when the process image matches `powershell.exe`. This tiered approach (broad collection → specific high-fidelity alert) is a core SIEM detection-engineering pattern.

### 6. Advanced Platform Features
* **Active Response:** Reviewed automated remediation actions (script execution, file deletion, connection blocking) triggered on rule match.
* **File Integrity Monitoring (FIM):** Explored tracking of unauthorized changes to critical files, registry keys, and sensitive configs (e.g. SSH keys) — a common compliance requirement (PCI-DSS, HIPAA).
* **Malware Detection via FIM:** Noted Wazuh's YARA and VirusTotal integration, which scans modified files on-the-fly and can trigger containment via Active Response.
* **Compliance Mapping:** Confirmed default Wazuh rules auto-map detected events to MITRE ATT&CK, GDPR, and PCI-DSS — relevant for GRC-adjacent SOC work.

---

## 💡 Practical SOC Application
This lab reflects work that sits one layer below alert triage — the configuration and tuning that makes triage possible in the first place:
* **Rule tuning** (like the PowerShell detection chain above) is exactly how a SOC reduces alert fatigue — broad logging with narrow, high-fidelity alerting rather than flagging everything.
* **CIS Benchmark scoring** gives a SOC/GRC team a defensible, auditable way to report security posture to stakeholders beyond just "alerts handled."
* **Vulnerability Detection** output (CVE lists) feeds directly into patch-prioritization conversations with IT — a common SOC L1 → IT handoff.

---

## 📌 Key Takeaways & Skills Demonstrated
* **Unified XDR Management:** Deploying, managing, and navigating a centralized Wazuh SIEM/XDR environment end-to-end.
* **Endpoint Hardening & Auditing:** Using IT Hygiene and CIS compliance benchmarks to identify host misconfigurations.
* **Detection Engineering:** Understanding the full log lifecycle — collection, decoding (parsing), rule authorship, and severity-based alerting (levels 1–15).
* **Threat Hunting:** Querying raw event data to surface a real malware family signature (Cobalt Strike), not just relying on pre-built alerts.
