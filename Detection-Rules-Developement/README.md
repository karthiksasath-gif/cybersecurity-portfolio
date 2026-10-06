# Project Report: Security Detection Engineering & Attack Chain Analysis

**Lab Environment:** TryHackMe — Detection Engineering: Developing Detections (Elastic Security)

## 1. Executive Summary
This report outlines the end-to-end process of threat research, detection rule authoring, validation, and tuning carried out across an attack chain spanning reconnaissance, brute-force attacks, credential dumping, and lateral movement. As security environments evolve, relying solely on signature-based or atomic alerts results in alert fatigue and blind spots. This project demonstrates the implementation of four core detection methodologies — **Atomic**, **Stateful**, **Correlation-based**, and **Anomaly-based** detections — alongside iterative detection tuning principles to ensure high-confidence, actionable alerting for the Security Operations Center (SOC).

---

## 2. Project Overview & Methodology
The project followed a structured engineering lifecycle:
1. **Threat Research:** Understanding adversary techniques via MITRE ATT&CK framework mappings and analyzing raw telemetry logs.
2. **Rule Authoring:** Deploying tailored detection rules utilizing query languages such as KQL (Kusto Query Language) and EQL (Event Query Language).
3. **Testing & Validation:** Performing historical rule preview tests against specific attack windows to evaluate true positive and false positive rates.
4. **Tuning:** Applying tuning techniques (grouping, threshold adjustments, suppression, and refactoring) to refine alert fidelity.

![Research process — identifying log sources for RDP brute-force](screenshot/Research%20Process/1.png)
![Baselining normal RDP authentication behavior](screenshot/Research%20Process/3.png)

---

## 3. Implemented Detection Rules

### A. Reconnaissance Detection (Atomic)
* **Objective:** Detect low-level reconnaissance commands (`whoami.exe`, `net.exe`, `nltest.exe`, `ipconfig.exe`, `systeminfo.exe`) commonly executed during the initial stages of an intrusion.
* **Challenge:** Administrators run these commands legitimately during routine troubleshooting, generating high-volume false positives when configured as raw atomic detections.
* **Rule Built:** Custom Query rule matching process-creation events for the recon command set, refined during research to remove a false positive (`ngentask.exe`) and add a missed recon tool (`nltest.exe`).
* **Metadata:** *T1059.001 – Suspicious Reconnaissance Command Execution*, Severity: Low, MITRE: Discovery (T1082, T1087).
* **Result:** 22 alerts generated — one per recon command execution, confirming the rule fires reliably but, as expected for an atomic rule, produces high alert volume.

![Atomic detection rule configuration](screenshot/Atomic%20Detection/6.png)
![Rule preview — 22 alerts generated](screenshot/Atomic%20Detection/8.png)

### B. Credential Access & Brute-Force Detection (Stateful)
* **Objective:** Distinguish a high-volume password spray attempt from normal failed-login noise.
* **Solution:** Built a Threshold rule grouped by `source.ip`, counting `user.name` with a minimum cardinality of 5 distinct accounts and a threshold of 10 failures — this shifts detection from "one account under attack" to "many accounts sprayed from one source."
* **Metadata:** *T1110.001 – RDP Brute Force: Password Guessing*, Severity: Medium, Risk score: 47.
* **Result:** 1 alert generated, correctly identifying attacker IP `5.62.18.132` with 50 total failures across 10 distinct usernames tested.

![Threshold rule — grouping and cardinality configuration](screenshot/Stateful%20Detection/9.png)
![Rule preview confirming the password spray](screenshot/Stateful%20Detection/12.png)

### C. Successful Access Confirmation (Correlation)
* **Objective:** Answer the more urgent question a threshold alert can't: not just "someone is spraying," but "did they get in?"
* **Solution (EQL Sequence Correlation):** Wrote an EQL correlation rule linking 10+ failed login attempts with a subsequent successful RDP authentication sharing the same source IP within a 5-minute window.
```eql
  sequence by source.ip with maxspan=5m
    [authentication where event.code == 4625 and winlog.event_data.LogonType == 3] with runs = 10
    [authentication where event.code == 4624 and winlog.event_data.LogonType == 10]
```
* **Metadata & Risk Scoring:** Named *T1110.003 – RDP Password Spray: Successful Logon Following Multiple Failures*, Severity escalated from Medium to **High**, risk score **73** — reflecting that confirmed access is a materially different risk than spraying alone.
* **Suppression & Deduplication:** Identified that `with runs=10` matches "at least 10" rather than "exactly 10," generating duplicate alerts from overlapping valid sequences. Resolved by configuring alert suppression on `source.ip`, deduplicating matches within the time window to a single actionable alert.

![EQL correlation rule — sequence configuration](screenshot/Correlation%20Based%20Detection/14.png)
![Correlation alert confirming successful access after spray](screenshot/Correlation%20Based%20Detection/16.png)

### D. Lateral Movement & Behavioral Anomaly Detection
* **Objective:** Detect technique-agnostic lateral movement (e.g., PsExec-based service installations like `PSEXESVC`, or renamed variants like `EvilService`) without relying on rigid signatures that an attacker can defeat by renaming a binary.
* **Approach:** Since ML anomaly jobs require an Elastic Platinum/Enterprise license unavailable in this lab, anomaly detection was demonstrated conceptually via Discover: baselining service-creation events (`event.code: 7045`) on `app-01` across a quiet period, then showing the clear deviation during the attack window.
* **Why it matters:** An atomic rule matching `ServiceName == PSEXESVC` is defeated the instant an attacker renames the service. A behavioral baseline flags *any* unexpected service installation on a host that rarely sees them — catching the technique regardless of the tool name used.

![Service-creation baseline vs. attack-window spike](screenshot/Anamoly%20Detection/18.png)

### E. Detection Tuning — Reworking the Recon Rule
* **Problem:** The atomic recon rule from Section A generates 22 alerts for legitimate admin activity just as readily as attacker activity — unsustainable at SOC scale.
* **Fix Applied (Full Rework):** Converted the atomic rule into a **Threshold rule**, grouped by `host.name` AND `winlog.event_data.LogonId` (not just host), with a threshold of ≥3 distinct recon commands within the same logon session. Grouping by LogonId specifically — rather than just host — ties every recon command back to one intrusion session, so a legitimate admin and an attacker active on the same host don't get conflated.
* **Result:** Alert volume dropped from 22 individual alerts to **1 alert**, correctly isolating the attacker's session (LogonId `0x557e9`) while remaining silent on routine admin troubleshooting.

![Reworked threshold rule — grouped by host and LogonId](screenshot/Detection%20Tuning/19.png)

---

## 4. Key Findings & Lessons Learned

| Detection Type | Primary Strength | Main Vulnerability / Trade-off |
| :--- | :--- | :--- |
| **Atomic** | Simple to write; catches specific known behaviors. | High false-positive rate; easily bypassed by minor technique changes. |
| **Stateful / Threshold** | Reduces noise by requiring volume or repetition. | Can miss slow-and-low stealth attacks if thresholds are set too high. |
| **Correlation** | High confidence; connects multi-phase attack kill chains. | Complex to maintain; breaks silently if any single log step is missing. |
| **Anomaly** | Technique-agnostic; catches unknown or novel tool variations. | Requires clean historical training data; prone to false alerts during organizational changes. |

* **Tuning is Mandatory:** Every rule degrades over time when exposed to live production traffic. Iterative allowlisting, threshold adjustments, and field enrichment are essential to maintain SOC efficiency and eliminate alert fatigue. The recon rule rework (Section E) is a concrete example: the same detection intent, rebuilt with better grouping logic, cut alert volume by 95% without losing the attacker's session.

---

## 5. Conclusion & Next Steps
This project established a robust foundation for end-to-end detection engineering, moving telemetry from unprioritized noise to high-confidence, actionable threat alerts. Future steps include migrating these detection engineering concepts into vendor-agnostic frameworks (such as Sigma rules) to ensure portability across multi-vendor SIEM ecosystems like Splunk, Microsoft Sentinel, and Elastic Security.
