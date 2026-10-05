# SOC Investigation Report: SIEM Alert Triage & Queue Management

**Lab Environment:** TryHackMe — Simulated SOC SIEM environment

## Executive Summary
This project documents a hands-on Security Operations Center (SOC) alert triage exercise performed within a simulated SIEM environment. The objective was to process an active alert queue, apply prioritization logic, conduct technical telemetry analysis, determine accurate verdicts (True Positive vs. False Positive), and document analyst notes.

| Case | Severity | Verdict |
| :--- | :--- | :--- |
| Potential Data Exfiltration (Zoom traffic) | Critical | False Positive |
| Double-Extension File Creation (`.mp4.exe`) | High | **True Positive** |
| Download from GitHub Repository | Low | False Positive |

---

## Methodology & Triage Workflow
To prevent alert fatigue and ensure rapid containment of active security breaches, the investigation followed a standardized SOC workflow:
1. **Queue Review & Prioritization:** Filtered active unassigned alerts, sorting primarily by **Severity** (Critical -> High -> Medium -> Low) and secondarily by **Time** (handling older alerts first to mitigate attacker dwell time).
2. **Assignment & Status Change:** Claimed ownership of each alert by assigning it to the analyst profile and updating its status from *Awaiting Action* to *In Progress*.
3. **Telemetry Inspection:** Reviewed alert descriptions, rule logic, source IPs, usernames, hostnames, and contextual metadata.
4. **Verdict Formulation & Documentation:** Evaluated technical legitimacy, documented findings via analyst notes, set appropriate verdicts, and transitioned tickets to *Closed*.

![Alert queue — Events and Alerts view](screenshots/1.%20Events%20and%20Alerts/1.png)
![Alert properties panel](screenshots/2.%20Alert%20Properties/1.png)
![Queue sorted by severity and time](screenshots/3.%20Alert%20Prioritization/1.png)

---

## Incident Triage Case Studies

### 1. Potential Data Exfiltration (Critical Priority)
* **Timestamp & Severity:** Mar 21, 2025 at 13:30 | **Critical**
* **Telemetry Data:**
  * Source Host/Network: `UK04/MEETINGROOM` (`192.168.45.66`)
  * Destination: `*.zoom.us`
  * Data Volumes: 5.8 GB Sent / 5.2 GB Received
* **Analysis:** Although volume crossed the >5GB threshold rule, the destination field confirmed traffic routed to legitimate Zoom video conferencing servers from an active meeting room.
* **Verdict:** **False Positive (No Threat)**
* **Analyst Note:** *"Alert triggered due to volume threshold (>5GB) to an external destination. Destination IP reviewed and confirmed as Zoom (*.zoom.us) traffic from a meeting room device. Concluded as benign video conferencing activity. Verdict: False Positive."*

![Case 1 — alert detail and verdict](screenshots/4.%20Alert%20Triage/1.png)
![Case 1 — closed ticket](screenshots/4.%20Alert%20Triage/2.png)

---

### 2. Double-Extension File Creation (High Priority)
* **Timestamp & Severity:** Mar 21, 2025 at 13:58 | **High**
* **Telemetry Data:**
  * Host / User: `LPT-HR-009` / `S.Conway`
  * Process Name & Target File: `chrome.exe` -> `C:\Users\S.Conway\Downloads\cats2025.mp4.exe`
  * Mark-of-the-Web (MotW): `https://freecatvideoshd.monster/cats2025.mp4.exe`
* **Analysis:** The file uses a classic social-engineering obfuscation tactic — hiding an executable behind a fake media extension (`.mp4.exe`) — downloaded via a malicious external lure domain.
* **Verdict:** **True Positive (Real Threat)**
* **Analyst Note:** *"Alert triggered by double-extension file creation (.mp4.exe) downloaded via Chrome by user S.Conway on host LPT-HR-009. Source URL indicates a malicious lure (freecatvideoshd.monster). Confirmed as a phishing/malware delivery attempt. Verdict: True Positive."*

![Case 2 — malicious file detection](screenshots/4.%20Alert%20Triage/3.png)
![Case 2 — investigation evidence](screenshots/4.%20Alert%20Triage/4.png)

**Recommended Actions:**
1. Isolate host `LPT-HR-009` from the network pending cleanup.
2. Quarantine/delete `cats2025.mp4.exe` and verify no further execution occurred (check process creation logs for `cats2025.mp4.exe` spawning child processes).
3. Block the lure domain `freecatvideoshd.monster` at the web proxy/DNS layer.
4. Notify user S.Conway and provide phishing-awareness guidance given the social-engineering vector.
5. Escalate to Tier 2 / IR team if lateral movement or persistence indicators are found during host triage.

---

### 3. Download from GitHub Repository (Low Priority)
* **Timestamp & Severity:** Mar 21, 2025 at 13:02 | **Low**
* **Telemetry Data:**
  * Host / User / Network: `LPT-IT-063` / `G.Chandler` / `VPN/DEVELOPERS`
  * Accessed URL: `https://github.com/facebook/react`
* **Analysis:** Rule triggers on external code downloads. Inspection confirmed access to the official, trusted open-source React repository maintained by Meta, by an authorized developer.
* **Verdict:** **False Positive (No Threat)**
* **Analyst Note:** *"Alert triggered by a download from GitHub. URL inspected and verified as the official React repository (github.com/facebook/react) accessed by developer G.Chandler on IT host LPT-IT-063. Confirmed as authorized, benign developer workflow. Verdict: False Positive."*

![Case 3 — GitHub download alert detail](screenshots/4.%20Alert%20Triage/5.png)
![Case 3 — closed ticket](screenshots/4.%20Alert%20Triage/6.png)

---

## Key Takeaways
* Automated SIEM rules frequently flag high-volume or dual-use legitimate operations (e.g. Zoom streams, developer repositories) that require human context to correctly filter out as false positives.
* Prioritizing alerts by severity and timestamp ensures high-impact threats are handled first and reduces attacker dwell time.
* A confirmed True Positive isn't the end of the workflow — containment and remediation steps (host isolation, domain blocking, user notification) are part of closing the loop, not just the detection itself.
