# Incident Investigation Report: Compromise Analysis of THM-PC

**Lab Environment:** TryHackMe — Host: THM-PC (simulated breach investigation)
**Overall Severity: Critical** — full kill chain from credential compromise to active C2 communication

---

## Executive Summary
Forensic investigation of a simulated security breach on host **THM-PC**, using Windows Security Event logs, Sysmon telemetry, and PowerShell history artifacts to reconstruct the attacker's full kill chain. The intrusion began with credential compromise and privilege escalation, moved through user activity leading to malware execution via Google Chrome, established persistence via a Start Menu URL shortcut, communicated with an external Command and Control (C2) server, and concluded with malicious PowerShell activity and enumeration by user `thm.bob`.

---

## Incident Timeline & Kill Chain Analysis

### 1. Privilege Escalation & Persistence Setup (Windows Security Logs)
* **Local Account Creation:** On `5/18/2025` at `10:54:58 PM`, an unauthorized local account named `svc_sysrestore` was created under the compromised `Administrator` session (`SubjectLogonId 0x183c36d`), designed to blend in as a legitimate service account.
* **Security Group Modification:** The new account was immediately added to high-privilege local groups (Built-in Users, Remote Desktop Users, and **Backup Operators**) to enable remote access and file read/write access across the file system.

![Unauthorized account creation — Security Event Log](screenshots/1.Security%20Log%20-%20Authentication/1.png)
![svc_sysrestore added to Backup Operators group](screenshots/2.Security%20Log%20-%20User%20Management/1.png)

### 2. Initial Access & Execution (Sysmon Process Monitoring)
* **Browser Activity:** User **sarah.miller** browsed the web via **Google Chrome** (`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`).
* **Malware Download:** A malicious executable (`ckjg.exe`) was downloaded into `C:\Users\sarah.miller\Downloads\` from the external URL `http://gettsveriff.com/bgj3/ckjg.exe`, confirmed via Zone.Identifier stream tracking.
* **Execution:** At `16:08:43 UTC`, `ckjg.exe` was executed by user `sarah.miller`.

![ckjg.exe execution — Sysmon Event ID 1](screenshots/3.Sysmon%20-%20Process%20Monitoring/1.png)

### 3. Persistence & Network Command & Control (Sysmon File & Network Events)
* **Persistence Mechanism:** The malware established host persistence by creating a shortcut file (`DeleteApp.url`) inside the Startup directory: `C:\Users\sarah.miller\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\DeleteApp.url`.
* **DNS Query:** The malware resolved the domain `hkfasfsafg.click`, which mapped to the malicious IP address below.
* **C2 Connection:** An active TCP connection was observed from host IP `10.10.57.125` (Port `50558`) to the Command & Control server at **`193.46.217.4:7777`**.

![Startup persistence — DeleteApp.url creation](screenshots/4.Sysmon%20-%20Files%20%26%20Network/1.png)
![C2 network connection — Sysmon Event ID 3](screenshots/4.Sysmon%20-%20Files%20%26%20Network/2.png)

### 4. Post-Exploitation & Reconnaissance (PowerShell Logging)
* **System Commands:** Analysis of PowerShell logs and PSReadLine history (`ConsoleHost_history.txt`) revealed extensive administrative and recon activity, including `Get-ComputerInfo`, modifying DNS server addresses, disabling Terminal Services/Remote Desktop (`Set-Service -Name "TermService" -StartupType Disabled`), and saving the registry hive (`reg save HKLM\SYSTEM C:\Windows\Temp\system.bak`).
* **Flag Creation:** User `thm.bob` executed commands to enumerate local users, SMB shares, and network interfaces, concluding with creation of a flag file.

![PowerShell recon commands — ConsoleHost_history.txt](screenshots/5.Powershell%20-%20Logging%20Monitoring/1.png)

---

## Indicators of Compromise (IoCs)

* **Malicious File Paths:**
  * `C:\Users\sarah.miller\Downloads\ckjg.exe`
  * `C:\Users\sarah.miller\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\DeleteApp.url`
* **Network Indicators:**
  * **C2 IP/Port:** `193.46.217.4:7777`
  * **Domain:** `hkfasfsafg.click`
  * **Download URL:** `http://gettsveriff.com/bgj3/ckjg.exe`
* **Compromised Accounts / Users:**
  * `svc_sysrestore` (Unauthorized local user)
  * `sarah.miller` (Initial download/execution vector)
  * `thm.bob` (Post-exploitation recon user)

---

## Conclusion & Recommendations
The system underwent a targeted attack resulting in credential abuse, privilege escalation via local group modification, malware execution, startup folder persistence, and external C2 communication.

**Recommended Action Items:**
1. Isolate **THM-PC** from the network immediately.
2. Terminate the malicious process (`ckjg.exe`) and remove the unauthorized startup link (`DeleteApp.url`).
3. Delete the unauthorized administrative account `svc_sysrestore` and audit all recent changes to the Backup Operators group.
4. Block external communications to IP address `193.46.217.4` and domain `hkfasfsafg.click` at the firewall.
5. Revoke and rotate credentials for affected user profiles (`sarah.miller`, `thm.bob`, and administrative accounts).
6. Submit `ckjg.exe` and the domain `hkfasfsafg.click` to threat intelligence platforms (VirusTotal, AlienVault OTX) to check for related campaign indicators.
