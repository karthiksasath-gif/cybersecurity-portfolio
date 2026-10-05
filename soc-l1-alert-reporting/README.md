# SOC L1 Alert Triage, Investigation, and Escalation

**Lab Environment:** TryHackMe — Simulated SOC environment

## Project Overview
This project documents the end-to-end triage, investigation, and escalation workflow for security alerts within a simulated Security Operations Center (SOC) environment. The objectives include evaluating alerts, determining true positives (TP), executing proper containment and communication steps, and escalating complex incidents to Tier 2 (L2) analysts.

---

## Incident Summary Table

| Incident Time | Alert Name | Severity | Verdict | Assignee / Escalation |
| :--- | :--- | :--- | :--- | :--- |
| **Mar 27, 2025 - 18:30** | Sensitive Document Share to External | Medium | True Positive | Escalated to E.Fleming (L2) |
| **Mar 27, 2025 - 19:25** | Email Marked as Phishing after Delivery | Medium | True Positive | Escalated to E.Fleming (L2) |
| **Mar 27, 2025 - 19:56** | Spike of Domain Discovery Commands | **High** | True Positive | Escalated to E.Fleming (L2) |

---

## Detailed Incident Breakdown & Analyst Reports

### 1. Sensitive Document Share to External
**Severity: Medium**

* **Source User:** `m.boslan@tryhackme.thm` (Martin Boslan, HR Lead)
* **Device / Location:** Trusted device `LPT-HR-0988` via Google Workspace
* **Target / File:** External ProtonMail address (`shadow18562@protonmail.thm`) / `Employee Records (Updated)` spreadsheet
* **Analyst Report / Comment:**
  > At 18:30 UTC, m.boslan@tryhackme.thm (Martin Boslan, HR Lead) logged in to Google Workspace from trusted device LPT-HR-0988. One minute later, a bulk download attempt of the full HR folder was blocked by DLP. Shortly after, Martin shared the "Employee Records (Updated)" spreadsheet with an unidentified external address, shadow18562@protonmail.thm. No further exfiltration confirmed. Escalating to communicate with Martin directly and notify the Compliance team.

* **Evidence:**
  ![Sensitive Document Share Triage](screenshots/1.Reporting%20Guide/1.png)

* **Recommended Actions:**
  1. Contact Martin Boslan directly to confirm intent and context for the share.
  2. Attempt to recall/revoke access to the shared document if the platform supports it.
  3. Notify the Compliance/Legal team given this involves HR/employee PII.
  4. Review Martin's account for any other unusual external-sharing activity in the prior 30 days.

---

### 2. Email Marked as Phishing after Delivery
**Severity: Medium**

* **Sender / Recipient:** `support@microsoft.com` (Spoofed) to `e.huffman@tryhackme.thm` (Eddie Huffman, IT Manager)
* **Subject & Payload:** *"Important Update: Microsoft Teams Pricing Increase"* containing a malicious attachment (`REPORT.rar`).
* **Security Check Status:** `SPF: Fail`, `DKIM: Fail`
* **Analyst Report / Comment:**
  > At 18:45 UTC, e.huffman@tryhackme.thm (Eddie Huffman, IT Manager) received an inbound external email flagged post-delivery as phishing, spoofing support@microsoft.com, subject "Important Update: Microsoft Teams Pricing Increase." Email gateway confirmed SPF and DKIM failures, consistent with sender spoofing.

* **Evidence:**
  ![Phishing Alert Details](screenshots/1.Reporting%20Guide/2.png)
  ![Phishing Escalation View](screenshots/1.Reporting%20Guide/3.png)

* **Recommended Actions:**
  1. Purge the email from Eddie Huffman's mailbox and search/remove it from any other inboxes it was delivered to.
  2. Confirm the `REPORT.rar` attachment was not opened/executed; if opened, isolate the host immediately.
  3. Block the spoofed sending domain/IP at the email gateway.
  4. Send a brief phishing-awareness notice to staff referencing this lure, since it was delivered post-perimeter-bypass.

---

### 3. Spike of Domain Discovery Commands
**Severity: High**

* **Host & OS:** `DMZ-MSEXCHANGE-2013` (Windows Server 2012 R2) running under `NT AUTHORITY\SYSTEM`
* **Execution Process Chain:** `C:\Windows\System32\inetsrv\w3wp.exe` → `C:\Users\Public\revshell.exe` → `C:\Windows\System32\cmd.exe`
* **Invoked Commands:** `whoami /priv`, `net group "Domain Admins" /domain`, `nltest /dclist:tryhackme.thm`
* **Analyst Report / Comment:**
  > At 19:12 UTC, on host DMZ-MSEXCHANGE-2013 (Windows Server 2012 R2) running under NT AUTHORITY\SYSTEM, cmd.exe spawned from an unauthorized parent process (C:\Users\Public\revshell.exe) and executed Active Directory enumeration commands, including whoami /priv, net group "Domain Admins" /domain, and nltest /dclist:tryhackme.thm. Indicates post-exploitation reconnaissance via a web-shell-spawned reverse shell on a DMZ-facing Exchange server.

* **Evidence:**
  ![Domain Discovery Escalation](screenshots/2.Escalation%20Guide/4.png)

* **Recommended Actions:**
  1. Isolate `DMZ-MSEXCHANGE-2013` from the network immediately — this is a DMZ-facing server with an active reverse shell.
  2. Terminate `revshell.exe` and identify the initial web-shell drop via `w3wp.exe` (likely an unpatched Exchange vulnerability — check for known CVEs against this Exchange build).
  3. Treat `NT AUTHORITY\SYSTEM`-level compromise as a potential precursor to full domain compromise; prioritize for IR/L2 pickup over the other two cases.
  4. Audit for any successful Domain Admin group changes or lateral movement following the enumeration commands.
  5. Patch/harden the Exchange server post-containment before returning it to production.

---

## Escalation & Communication Workflow
Following standard SOC operating procedures, all True Positive alerts were processed through the standard L1 lifecycle:
1. **Assignment & Status:** Picked up from the queue, assigned to the active L1 analyst, and updated to **In Progress**.
2. **Investigation & Documentation:** Technical indicators and telemetry analyzed, verdicts set to **True Positive**, and detailed investigative comments recorded.
3. **Escalation:** Reassigned to the on-shift Tier 2 analyst (`E.Fleming (L2)`) for containment, compliance reporting, and incident response handling.

![Escalation ticket — handoff to L2](screenshots/2.Escalation%20Guide/5.png)
![Escalation ticket — L2 assignment confirmed](screenshots/2.Escalation%20Guide/6.png)
