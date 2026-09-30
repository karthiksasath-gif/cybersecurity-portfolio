# Incident Investigation Report: Compromise Analysis of THM-PC

---

## Executive Summary
This report details the forensic investigation I conducted independently on a simulated security breach on host **THM-PC**. Through analyzing Windows Security Event logs, Sysmon telemetry, and PowerShell history artifacts, I successfully mapped the attacker's full kill chain. The intrusion began with credential compromise and privilege escalation, moved through user activity leading to malware execution via Google Chrome, established persistence via a Start Menu URL shortcut, communicated with an external Command and Control (C2) server, and concluded with malicious PowerShell activity and enumeration by user `thm.bob`.

---

## Incident Timeline & Kill Chain Analysis

### 1. Privilege Escalation & Persistence Setup (Windows Security Logs)
* **Local Account Creation:** On `5/18/2025` at `10:54:58 PM`, I identified that an unauthorized local account named `svc_sysrestore` was created under the compromised `Administrator` session (`SubjectLogonId 0x183c36d`) to blend in as a legitimate service[cite: 8, 9, 15].
* **Security Group Modification:** I found that the new account was immediately added to high-privilege local groups (Built-in Users, Remote Desktop Users, and **Backup Operators**) to enable remote access and file read/write access across the file system[cite: 10, 11, 13].

### 2. Initial Access & Execution (Sysmon Process Monitoring)
* **Browser Activity:** I tracked that the user **sarah.miller** browsed the web via **Google Chrome** (`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`)[cite: 16, 17, 18].
* **Malware Download:** I discovered a malicious executable (`ckjg.exe`) downloaded into `C:\Users\sarah.miller\Downloads\` from the external URL `http://gettsveriff.com/bgj3/ckjg.exe` via Zone.Identifier stream tracking[cite: 18, 19].
* **Execution:** I recorded that at `16:08:43 UTC`, `ckjg.exe` was executed by user `sarah.miller`[cite: 18].

### 3. Persistence & Network Command & Control (Sysmon File & Network Events)
* **Persistence Mechanism:** I found that the malware established host persistence by creating a shortcut file (`DeleteApp.url`) inside the Startup directory: `C:\Users\sarah.miller\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\DeleteApp.url`[cite: 20].
* **DNS Query:** I identified that the malware resolved the domain `hkfasfsafg.click`, which mapped to the malicious IP address[cite: 22].
* **C2 Connection:** I observed an active TCP connection initiated from host IP `10.10.57.125` (Port `50558`) to the Command & Control server at **`193.46.217.4:7777`**[cite: 21].

### 4. Post-Exploitation & Reconnaissance (PowerShell Logging)
* **System Commands:** Through analyzing PowerShell logs and PSReadLine history (`ConsoleHost_history.txt`), I uncovered extensive administrative and recon activity, including running `Get-ComputerInfo`, modifying DNS server addresses, disabling Terminal Services/Remote Desktop (`Set-Service -Name "TermService" -StartupType Disabled`), and saving the registry hive (`reg save HKLM\SYSTEM C:\Windows\Temp\system.bak`)[cite: 23].
* **Flag Creation:** I tracked user `thm.bob` executing commands to enumerate local users, SMB shares, and network interfaces, concluding with the creation of a flag file[cite: 25].

---

## Indicators of Compromise (IoCs)

* **Malicious File Paths:**
  * `C:\Users\sarah.miller\Downloads\ckjg.exe`[cite: 18, 19]
  * `C:\Users\sarah.miller\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\DeleteApp.url`[cite: 20]
* **Network Indicators:**
  * **C2 IP/Port:** `193.46.217.4:7777`[cite: 21]
  * **Domain:** `hkfasfsafg.click`[cite: 22]
  * **Download URL:** `http://gettsveriff.com/bgj3/ckjg.exe`[cite: 19]
* **Compromised Accounts / Users:**
  * `svc_sysrestore` (Unauthorized local user)[cite: 9]
  * `sarah.miller` (Initial download/execution vector)[cite: 18]
  * `thm.bob` (Post-exploitation recon user)[cite: 25]

---

## Conclusion & Recommendations
The system underwent a targeted attack resulting in credential abuse, privilege escalation via local group modification, malware execution, startup folder persistence, and external C2 communication. 

**Recommended Action Items:**
1. Isolate **THM-PC** from the network immediately.
2. Terminate malicious processes (`ckjg.exe`) and remove the unauthorized startup link (`DeleteApp.url`)[cite: 18, 20].
3. Delete the unauthorized administrative account `svc_sysrestore` and audit all recent changes to the Backup Operators group[cite: 9, 10, 11].
4. Block external communications to IP address `193.46.217.4` and domain `hkfasfsafg.click` at the firewall[cite: 21, 22].
5. Revoke and rotate credentials for affected user profiles (`sarah.miller`, `thm.bob`, and administrative accounts).
