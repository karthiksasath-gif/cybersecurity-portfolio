# SOC Investigation Report: SIEM Alert Triage & Queue Management

## Executive Summary
This project documents a hands-on Security Operations Center (SOC) alert triage exercise performed within a simulated SIEM environment. The objective was to process an active alert queue, apply strict prioritization logic, conduct technical telemetry analysis, determine accurate verdicts (True Positive vs. False Positive), and document professional analyst notes.

---

## Methodology & Triage Workflow
To prevent alert fatigue and ensure rapid containment of active security breaches, the investigation followed a standardized SOC workflow:
1. **Queue Review & Prioritization:** Filtered active unassigned alerts, sorting primarily by **Severity** (Critical -> High -> Medium -> Low) and secondarily by **Time** (handling older alerts first to mitigate attacker dwell time).
2. **Assignment & Status Change:** Claimed ownership of each alert by assigning it to the analyst profile and updating its status from *Awaiting Action* to *In Progress*.
3. **Telemetry Inspection:** Reviewed alert descriptions, rule logic, source IPs, usernames, hostnames, and contextual metadata.
4. **Verdict Formulation & Documentation:** Evaluated technical legitimacy, documented findings via professional analyst notes, set appropriate verdicts, and transitioned tickets to *Closed*.

---

## Incident Triage Case Studies

### 1. Potential Data Exfiltration (Critical Priority)
* **Timestamp & Severity:** Mar 21, 2025 at 13:30 | **Critical**
* **Telemetry Data:** 
  * Source Host/Network: `UK04/MEETINGROOM` (`192.168.45.66`)
  * Destination: `*.zoom.us`
  * Data Volumes: 5.8 GB Sent / 5.2 GB Received
* **Analysis & Verdict:** Although volume crossed the $>5\text{GB}$ threshold rule, external destination fields confirmed traffic routed to legitimate Zoom video conferencing servers from an active meeting room. 
* **Verdict:** **False Positive (No Threat)**
* **Analyst Note:** *"Alert triggered due to volume threshold (>5GB) to an external destination. Further investigation of destination IP reveals traffic routed to Zoom (*.zoom.us) from a meeting room device. Concluded as benign video conferencing activity. Verdict: False Positive."*

### 2. Double-Extension File Creation (High Priority)
* **Timestamp & Severity:** Mar 21, 2025 at 13:58 | **High**
* **Telemetry Data:**
  * Host / User: `LPT-HR-009` / `S.Conway`
  * Process Name & Target File: `chrome.exe` -> `C:\Users\S.Conway\Downloads\cats2025.mp4.exe`
  * Mark-of-the-Web (MotW): `https://freecatvideoshd.monster/cats2025.mp4.exe`
* **Analysis & Verdict:** The file employs a classic social engineering obfuscation tactic (hiding an executable behind a fake media extension `.mp4.exe`) downloaded via a malicious external lure domain. 
* **Verdict:** **True Positive (Real Threat)**
* **Analyst Note:** *"Alert triggered by double-extension file creation (.mp4.exe) downloaded via Chrome by user S.Conway on host LPT-HR-009. Source URL indicates a malicious lure (freecatvideoshd.monster). Confirmed as a phishing/malware delivery attempt. Verdict: True Positive."*

### 3. Download from GitHub Repository (Low Priority)
* **Timestamp & Severity:** Mar 21, 2025 at 13:02 | **Low**
* **Telemetry Data:**
  * Host / User / Network: `LPT-IT-063` / `G.Chandler` / `VPN/DEVELOPERS`
  * Accessed URL: `https://github.com/facebook/react`
* **Analysis & Verdict:** Rule triggers on external code downloads. Inspection confirms access to the official, trusted open-source React repository maintained by Meta on GitHub by an authorized developer.
* **Verdict:** **False Positive (No Threat)**
* **Analyst Note:** *"Alert triggered by a download from GitHub. URL inspected and verified as the official React repository (https://github.com/facebook/react) accessed by developer G.Chandler on IT host LPT-IT-063. Confirmed as authorized and benign developer workflow. Verdict: False Positive."*

---

## Key Takeaways
* Automated SIEM rules frequently capture high-volume or dual-use legitimate operations (such as Zoom streams or developer repositories) that require human context to accurately filter out as false positives.
* Prioritizing alerts by severity and timestamp ensures that high-impact threats are handled first.