# Project Report: Security Detection Engineering & Attack Chain Analysis

## 1. Executive Summary
This report outlines the end-to-end process of threat research, detection rule authoring, validation, and tuning carried out across an attack chain spanning reconnaissance, brute-force attacks, credential dumping, and lateral movement. As security environments evolve, relying solely on signature-based or atomic alerts results in alert fatigue and blind spots. This project demonstrates the implementation of four core detection methodologies—**Atomic**, **Stateful**, **Correlation-based**, and **Anomaly-based** detections—alongside iterative detection tuning principles to ensure high-confidence, actionable alerting for the Security Operations Center (SOC).

---

## 2. Project Overview & Methodology
The project followed a structured engineering lifecycle:
1. **Threat Research:** Understanding adversary techniques via MITRE ATT&CK framework mappings and analyzing raw telemetry logs.
2. **Rule Authoring:** Deploying tailored detection rules utilizing query languages such as KQL (Kusto Query Language) and EQL (Event Query Language).
3. **Testing & Validation:** Performing historical rule preview tests against specific attack windows to evaluate true positive and false positive rates.
4. **Tuning:** Applying tuning techniques (grouping, threshold adjustments, suppression, and refactoring) to refine alert fidelity.

---

## 3. Implemented Detection Rules

### A. Reconnaissance Detection (Atomic to Threshold Rework)
* **Objective:** Detect low-level reconnaissance commands (`whoami.exe`, `net.exe`, `nltest.exe`, `ipconfig.exe`, `systeminfo.exe`) commonly executed during the initial stages of an intrusion.
* **Challenge:** Administrators run these commands legitimately during routine troubleshooting, generating high-volume false positives when configured as raw atomic detections.
* **Solution (Threshold Tuning & Grouping):** Converted the atomic rule into a threshold rule grouped by session identifiers.
  * **KQL Filter:** `event.code: "1" AND (winlog.event_data.Image:"*whoami.exe*" OR "*net.exe*" OR "*nltest.exe*" OR "*ipconfig.exe*" OR "*systeminfo.exe*")`
  * **Grouping:** `host.name` and `winlog.event_data.LogonId` (specifically targeting the attacker's LogonId, e.g., `0x557e9`).
  * **Threshold:** Greater than or equal to 3 distinct commands within the same session window.

### B. Credential Access & Brute-Force Detection (Stateful & Correlation)
* **Objective:** Distinguish between a high-volume password spray attempt and an actual successful compromise.
* **Challenge:** Threshold alerts on failed logons tell the SOC *someone is spraying*, but fail to confirm if access was achieved.
* **Solution (EQL Sequence Correlation):** Wrote an EQL correlation rule linking failed login attempts with a subsequent successful RDP authentication sharing the same source IP within a strict time window.
  * **EQL Query:**
    ```eql
    sequence by source.ip with maxspan=5m
      [authentication where event.code == 4625 and winlog.event_data.LogonType == 3] with runs = 10
      [authentication where event.code == 4624 and winlog.event_data.LogonType == 10]
    ```
  * **Metadata & Risk Scoring:** Named *T1110.003 - RDP Password Spray: Successful Logon Following Multiple Failures*, configured with High severity and a risk score of **73**.
  * **Suppression & Deduplication:** Addressed multiple alert generations caused by multiple failing runs (`runs=10`) by implementing alert suppression based on `source.ip`.

### C. Lateral Movement & Behavioral Anomaly Detection
* **Objective:** Detect technique-agnostic lateral movement (such as PsExec-based service installations like `PSEXESVC` or renamed service variants like `EvilService`) without relying on rigid signatures.
* **Solution (Statistical Baseline Anomaly Detection):** Analyzed event telemetry for service creation events (`event.code: "7045"` on `app-01`). By examining historical frequency baselines, unexpected service installations during off-hours or by uncharacteristic accounts were flagged as statistical anomalies, catching attacks even when tool names or service names were obfuscated.

---

## 4. Key Findings & Lessons Learned

| Detection Type | Primary Strength | Main Vulnerability / Trade-off |
| :--- | :--- | :--- |
| **Atomic** | Simple to write; catches specific known behaviors. | High false-positive rate; easily bypassed by minor technique changes. |
| **Stateful / Threshold** | Reduces noise by requiring volume or repetition. | Can miss slow-and-low stealth attacks if thresholds are set too high. |
| **Correlation** | High confidence; connects multi-phase attack kill chains. | Complex to maintain; breaks silently if any single log step is missing. |
| **Anomaly** | Technique-agnostic; catches unknown or novel tool variations. | Requires clean historical training data; prone to false alerts during organizational changes. |

* **Tuning is Mandatory:** Every rule degrades over time when exposed to live production traffic. Iterative allowlisting, threshold adjustments, and field enrichment are essential to maintain SOC efficiency and eliminate alert fatigue.

---

## 5. Conclusion & Next Steps
This project established a robust foundation for end-to-end detection engineering, moving telemetry from unprioritized noise to high-confidence, actionable threat alerts. Future steps include migrating these detection engineering concepts into vendor-agnostic frameworks (such as Sigma rules) to ensure portability across multi-vendor SIEM ecosystems like Splunk, Microsoft Sentinel, and Elastic Security.