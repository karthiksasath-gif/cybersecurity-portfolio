# Project Report: SOC L1 Alert Triage, Investigation, and Escalation

## Project Overview
This project documents the end-to-end triage, investigation, and escalation workflow for security alerts within a simulated Security Operations Center (SOC) environment. The objectives include evaluating alerts, determining true positives (TP), executing proper containment and communication steps, and escalating complex incidents to Tier 2 (L2) analysts.

---

## Incident Summary Table

| Incident Time | Alert Name | Severity | Verdict | Assignee / Escalation |
| :--- | :--- | :--- | :--- | :--- |
| **Mar 27, 2025 - 18:30** | Sensitive Document Share to External | Medium | True Positive | Escalated to E.Fleming (L2) |
| **Mar 27, 2025 - 19:25** | Email Marked as Phishing after Delivery | Medium | True Positive | Escalated to E.Fleming (L2) |
| **Mar 27, 2025 - 19:56** | Spike of Domain Discovery Commands | Medium | True Positive | Escalated to E.Fleming (L2) |

---

## Detailed Incident Breakdown & Analyst Reports

### 1. Sensitive Document Share to External
* **Source User:** `m.boslan@tryhackme.thm` (Martin Boslan, HR Lead)
* **Device / Location:** Trusted device `LPT-HR-0988` via Google Workspace
* **Target / File:** External ProtonMail address (`shadow18562@protonmail.thm`) / `Employee Records (Updated)` spreadsheet
* **Analyst Report / Comment:**
  > At 18:30 UTC, m.boslan@tryhackme.thm (Martin Boslan, HR lead), logged in to their Google Workspace from a trusted LPT-HR-0988 device, and a minute later attempted to download the whole HR folder on their laptop, but was blocked by our DLP solution. A minute later, Martin shared the 'Employee Records (Updated)' spreadsheet to an unidentified shadow18562@protonmail.thm Protonmail email. Although no events are followed, escalating the alert to communicate with Martin and report the incident to the Compliance team.

* **Evidence:**
  ![Sensitive Document Share Triage](2.png)

---

### 2. Email Marked as Phishing after Delivery
* **Sender / Recipient:** `support@microsoft.com` (Spoofed) to `e.huffman@tryhackme.thm` (Eddie Huffman, IT Manager)
* **Subject & Payload:** *"Important Update: Microsoft Teams Pricing Increase"* containing a malicious attachment (`REPORT.rar`).
* **Security Check Status:** `SPF: Fail`, `DKIM: Fail`
* **Analyst Report / Comment:**
  > At 18:45 UTC, e.huffman@tryhackme.thm (Eddie Huffman, IT Manager) received an inbound external email flagged post-delivery as phishing, originating from support@microsoft.com with the subject "Important Update: Microsoft Teams Pricing Increase." The automated email gateway confirmed SPF and DKIM failures.

* **Evidence:**
  ![Phishing Alert Details](3.png)
  ![Phishing Escalation View](5.png)

---

### 3. Spike of Domain Discovery Commands
* **Host & OS:** `DMZ-MSEXCHANGE-2013` (Windows Server 2012 R2) running under `NT AUTHORITY\SYSTEM`
* **Execution Process Chain:** `C:\Windows\System32\inetsrv\w3wp.exe` $\rightarrow$ `C:\Users\Public\revshell.exe` $\rightarrow$ `C:\Windows\System32\cmd.exe`
* **Invoked Commands:** `whoami /priv`, `net group "Domain Admins" /domain`, `nltest /dclist:tryhackme.thm`
* **Analyst Report / Comment:**
  > At 19:12 UTC, on host DMZ-MSEXCHANGE-2013 (Windows Server 2012 R2) running under NT AUTHORITY\SYSTEM, a command interpreter (cmd.exe) spawned from an unauthorized parent process (C:\Users\Public\revshell.exe) executed Active Directory enumeration commands including whoami /priv, net group "Domain Admins" /domain, and nltest /dclist:tryhackme.thm.

* **Evidence:**
  ![Domain Discovery Escalation](6.png)

---

## Escalation & Communication Workflow
Following standard SOC operating procedures, all True Positive alerts were processed through the standard L1 lifecycle:
1. **Assignment & Status:** Picked up from the queue, assigned to the active L1 analyst, and updated to **In Progress**.
2. **Investigation & Documentation:** Technical indicators and telemetry analyzed, verdicts set to **True Positive**, and detailed investigative comments recorded.
3. **Escalation:** Reassigned to Tier 2 on-shift analyst (`E.Fleming (L2)`) for containment, compliance reporting, and incident response handling.