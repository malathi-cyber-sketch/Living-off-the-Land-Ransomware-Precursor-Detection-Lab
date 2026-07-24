# 🎯 SOC Response Guide — Ransomware Precursor Intrusion

![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-D62B1F?style=for-the-badge)
![Detect](https://img.shields.io/badge/Phase-Detect-yellow?style=for-the-badge)
![Respond](https://img.shields.io/badge/Phase-Respond-orange?style=for-the-badge)
![Recover](https://img.shields.io/badge/Phase-Recover-2ea44f?style=for-the-badge)

This document walks through the intrusion from both sides of the table: what the attacker actually did at each stage, and what a SOC analyst should be doing in response — detect, investigate, contain, eradicate, recover. Every stage below maps back to a real screenshot in this repo, and includes the log fields, IOCs, and detection logic I'd expect a real analyst to be looking at.

Think of this as the incident report I'd write if this had been a real ticket.

---

## Incident Summary

| Field | Value |
|---|---|
| **Host** | `windows10` (agent ID `002`), IP `192.168.100.4` |
| **Attacker source** | `192.168.100.3` (Kali Linux) |
| **Initial vector** | SMB credential brute force (Hydra) |
| **Compromised account** | `labuser` |
| **Highest severity alert** | Level 15 — "Multiple ransomware precursor techniques detected on same host within 5 minutes" (Wazuh rule `100220`) |
| **Outcome** | Simulated — no actual encryption occurred; investigation stopped at the precursor stage |

---

## Stage 1 — Reconnaissance

### 🔴 What the attacker did
Ran a full TCP port sweep (`nmap -p-`) against the target to map open services before touching anything else. Took just under two minutes and turned up SMB (445), RPC (135), NetBIOS (139), plus two less common ports (`7680/pando-pub`, `49667/unknown`) worth flagging as unusual.

```
sudo nmap 192.168.100.4 -p-
```

### 🔵 How a SOC analyst detects & investigates
- **Log source:** Network IDS/NIDS, firewall connection logs, NetFlow.
- **What to look for:** A single source IP making rapid, sequential connection attempts across a wide port range in a short window is the textbook signature of a port scan. Nmap's default timing also has a fairly recognizable connection cadence.
- **Query idea (Wazuh/ELK-style):** filter on `destination.port` cardinality per `source.ip` over a short time bucket — dozens of distinct destination ports from one source IP inside a minute or two is the tell.
- **Severity at this stage:** Low on its own. Reconnaissance happens constantly on any network (including from legitimate scanners) — it's a signal to watch, not an incident by itself.

### 🟢 Containment / response at this stage
- Log the source IP and correlate against known-good scanning schedules (vuln scanners, asset management tools) before acting.
- If unexpected: consider a firewall rule to rate-limit or block the source, and flag the host as a target of interest for the next 24–48 hours.

---

## Stage 2 — Credential Access (Brute Force)

### 🔴 What the attacker did
Pointed Hydra at the SMB service with a small username and password list. Worked through 24+ candidate usernames — root, support, helpdesk, service, backup, admin, etc. — all invalid, until one combination succeeded.

```
hydra -L usernames.txt -P password.txt smb://192.168.100.4
...
[445][smb] host: 192.168.100.4   login: labuser   password: Password123!
```

### 🔵 How a SOC analyst detects & investigates
- **Log source:** Windows Security Event Log (Event ID 4625 — failed logon), Event ID 4624 — successful logon on the target host; SMB server logs.
- **What to look for:** A burst of Event ID 4625 failures against the same account or targeting many different accounts from a single source IP in a short window, followed by a 4624 success. That pattern — many failures, one success, tight time window — is a brute force fingerprint almost every SIEM ships a rule for.
- **Wazuh specifics:** Wazuh's default ruleset has authentication-failure grouping rules; a custom rule (see example below) can also correlate SSH/SMB failures against a single source IP.
- **Password hygiene note:** `Password123!` technically meets a lot of "complexity" policies (upper/lower/digit/symbol) while still being trivially guessable — worth calling out in any real findings report. Complexity rules without a dictionary/breach check don't stop this.

**Example custom Wazuh rule used in this lab** (`local_rules_addition.xml`):
```xml
<rule id="100001" level="5">
  <if_sid>5716</if_sid>
  <srcip>1.1.1.1</srcip>
  <description>sshd: authentication failed from IP 1.1.1.1.</description>
  <group>authentication_failed,pci_dss_10.2.4,pci_dss_10.2.5,</group>
</rule>
```

### 🟢 Containment / response
1. **Immediate:** Disable or force a password reset on the compromised account (`labuser`) the moment the successful login is confirmed against a known brute-force pattern.
2. **Network:** Block or rate-limit the source IP at the firewall / SMB-facing ACL.
3. **Policy:** Enforce account lockout thresholds on SMB/RDP-facing accounts, and push toward MFA or at minimum a breached-password check (e.g., against Have I Been Pwned's password API) for any internet- or lateral-facing service.

---

## Stage 3 — Initial/Remote Access

### 🔴 What the attacker did
Used the cracked `labuser` credential to authenticate remotely. Wazuh flagged the pattern as NTLM authentication consistent with a pass-the-hash technique, tagged as a possible RDP connection.

### 🔵 How a SOC analyst detects & investigates
- **Log source:** Windows Security Event Log 4624 (Logon Type 3 = network, Logon Type 10 = RDP), Sysmon Event ID 3 (network connection).
- **Detection logic:** NTLM logons where the authentication package is NTLM rather than Kerberos, especially from a workstation-to-workstation path (not through a domain controller), are worth flagging — legitimate RDP in a managed environment usually goes through Kerberos when domain-joined.
- **Wazuh rule fired:** *"Successful Remote Logon Detected — User:\labuser — NTLM authentication, possible pass-the-hash attack — possible RDP connection"* (rule `92657`, level 6).
- **Pivot query:** search for all logon events tied to `labuser` in the following hour — did the account do anything a normal user account wouldn't (new service creation, registry writes, scheduled tasks)?

### 🟢 Containment / response
- Treat the account as compromised, not just the password. Reset credentials **and** review the account for any group membership changes.
- If pass-the-hash is confirmed or suspected, rotating the local Administrator password (and any shared local admin credentials across the fleet — this is exactly the lateral-movement risk pass-the-hash exploits) is critical, not just the one user account.
- Isolate the host from the network (EDR network-containment or VLAN quarantine) while investigation continues, since an active session means the attacker may still have a foothold.

---

## Stage 4 — Discovery

### 🔴 What the attacker did
Enumerated the environment post-logon: local users and SIDs (`Get-LocalUser`, `wmic useraccount get name,sid`), directory listings of `C:\`, running processes, and system info (`systeminfo`, `hostname`, `ipconfig`).

### 🔵 How a SOC analyst detects & investigates
- **Log source:** PowerShell Script Block Logging (Event ID 4104), Sysmon Event ID 1 (process creation), command-line auditing.
- **What to look for:** A cluster of discovery-oriented commands (`whoami`, `net user`, `wmic`, `Get-LocalUser`, `systeminfo`) run back-to-back by the same session, especially shortly after a new or unusual logon. Wazuh's default ruleset already tags a lot of this as "Discovery activity executed" (rule `92031`) — that low-severity tag becomes a lot more meaningful when it clusters right after an anomalous logon.
- **Why it matters:** Discovery commands alone are mostly harmless (sysadmins run them constantly) — context is everything. The signal is *timing and clustering*, not the commands themselves.

### 🟢 Containment / response
- No immediate containment action needed for discovery alone, but it's a strong corroborating signal to escalate the priority of the logon-anomaly alert from Stage 3.
- Document exactly what was enumerated — it tells you what the attacker now knows about the environment, which shapes what to expect next (in this case: account creation, since they now know the local user list).

---

## Stage 5 — Persistence

### 🔴 What the attacker did
Planted three separate footholds:
1. Created a new local account: `net user labuser Password123! /add` *(note: reused the same username/password already compromised — attacker convenience, defender's advantage)*
2. Added a `Run` registry key with a base64-looking value: `reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Updater /t REG_SZ /d "cG93ZXJzaGVsbCAtV2..." /f`
3. Created a scheduled task set to fire a binary at a specific time: `schtasks /create /sc once /tn TestTask /tr calc.exe /st 23:42`

### 🔵 How a SOC analyst detects & investigates
- **Log source:** Sysmon Event ID 13 (registry value set), Event ID 1 (process creation for `reg.exe`, `schtasks.exe`, `net.exe`), Windows Security Event 4720 (user account created).
- **Detection logic:**
  - New local account creation (4720) outside a change-management window is high-signal, especially on a workstation rather than an admin jump box.
  - Registry writes to `Run`/`RunOnce` keys are one of the most common persistence mechanisms (T1547.001) — Wazuh flagged this automatically: *"Value added to registry key has Base64-like pattern"* (rule `92041`, level 10). Base64 in a registry value is a strong indicator of an obfuscated payload, not a normal application setting.
  - `schtasks /create` run from a command shell (rather than Task Scheduler GUI) by a non-admin-looking process chain is worth an automatic medium/high alert.
- **IOC to hunt for:** any `Run`/`RunOnce` key value containing base64-like strings; any scheduled task not created via GPO/SCCM/normal deployment tooling.

### 🟢 Containment / response
- **Eradicate all three footholds**, not just the one you found first — attackers plant redundant persistence specifically so a single cleanup step doesn't kick them out. Checklist:
  - Disable/delete the rogue account.
  - Remove the malicious registry `Run` key.
  - Delete the scheduled task.
- Pull a full timeline of everything that account/session touched — don't assume you've found every mechanism until you've checked common persistence locations (Run keys, scheduled tasks, services, WMI event subscriptions, startup folder).

---

## Stage 6 — Defense Evasion

### 🔴 What the attacker did
Used two classic "living off the land" binaries (LOLBins):
- `mshta.exe vbscript:msgbox("Hello")` — proof-of-concept for arbitrary script execution via a trusted signed binary.
- `rundll32.exe shell32.dll,Control_RunDLL` — launches Control Panel through `rundll32`, again using a trusted binary as the launcher rather than a directly suspicious executable.

### 🔵 How a SOC analyst detects & investigates
- **Log source:** Sysmon Event ID 1 (process creation) with full command-line capture.
- **Why this is hard to catch with signature-based tools:** both `mshta.exe` and `rundll32.exe` are signed Microsoft binaries present on every Windows box. Antivirus won't flag the binary itself — detection has to be behavioral.
- **Detection logic:**
  - Flag `mshta.exe` with a `vbscript:` or `javascript:` URI in its command line — legitimate use of `mshta.exe` with inline script protocol handlers is rare outside of specific enterprise tooling.
  - Flag `rundll32.exe` invoking `shell32.dll,Control_RunDLL` or other non-standard DLL exports from a non-standard parent process (e.g., spawned from `cmd.exe` or `powershell.exe` rather than `explorer.exe`).
  - Parent-child process chain matters more than the binary name: `cmd.exe → rundll32.exe` is far more suspicious than `explorer.exe → rundll32.exe`.
- **Wazuh coverage in this lab:** a built-in Sysmon rule (`61638`) also caught a related suspicious process pattern involving `dllhost.exe`, mapped to GDPR, HIPAA, and TSC compliance controls.

### 🟢 Containment / response
- These techniques alone rarely warrant full incident escalation, but should be logged as corroborating evidence in the broader case file — they're a strong signal the attacker is actively trying to blend in, which raises confidence that everything else in the timeline is intentional, not accidental.
- Recommend application allow-listing (e.g., WDAC, AppLocker) with rules that restrict `mshta.exe` and unnecessary `rundll32` DLL exports where business need doesn't require them.

---

## Stage 7 — Impact Precursor (Shadow Copy Deletion) 🚨

### 🔴 What the attacker did
Ran the single most important command in this whole incident:

```
vssadmin delete shadows /all /quiet
```

This silently deletes every Volume Shadow Copy on the host — the local snapshots Windows uses for File History and "Previous Versions" restore. It's the step ransomware takes immediately before encryption so the victim can't simply roll back files from a local backup.

### 🔵 How a SOC analyst detects & investigates
- **Log source:** Sysmon Event ID 1 (process creation for `vssadmin.exe`), Windows Application/System event logs (VSS service events).
- **Detection logic:** `vssadmin.exe` with `delete shadows` in the command line should be a **near-automatic high-severity alert** in any environment. There are vanishingly few legitimate business reasons to run this command outside of a documented backup/storage maintenance window. Related commands worth the same treatment: `wbadmin delete catalog`, `wmic shadowcopy delete`, `bcdedit /set {default} recoveryenabled no`.
- **What Wazuh caught here:** this specific action was one of the triggers for the level-15 correlation alert (rule `100220`) — "Multiple ransomware precursor techniques detected on same host within 5 minutes." That's the correlation doing its job: `vssadmin` alone is a level-14 alert by itself in this ruleset, but stacked against the registry and scheduled-task activity from the same host in the same window, it escalates automatically.

### 🟢 Containment / response — this is where urgency changes
This is the point where a real SOC analyst stops "investigating calmly" and starts **incident response mode**:

1. **Isolate immediately.** Network-isolate the host (EDR containment, or physically/logically disconnect if no EDR agent). If ransomware deployment is imminent, minutes matter.
2. **Preserve evidence before touching anything else** — memory capture if tooling allows, disk image if the host is going to be rebuilt.
3. **Hunt laterally, fast.** Check every other host the compromised account touched. Shadow-copy deletion on one box strongly suggests the attacker is staging for a multi-host encryption event, not a single-machine annoyance.
4. **Check backups.** Confirm offline/immutable backups are intact and were not reachable/mountable from the compromised host (a lot of ransomware crews specifically hunt for and destroy connected backup targets too).
5. **Notify.** This is the threshold where most incident response plans require notifying leadership/legal, not just logging a ticket.

---

## Stage 8 — Eradication & Recovery

### 🔵 SOC checklist
- [ ] Disable/remove all attacker-created accounts and persistence mechanisms (registry keys, scheduled tasks, services).
- [ ] Reset credentials for the compromised account **and** any shared/local admin credentials it could have accessed.
- [ ] Patch or reconfigure the initial-access vector — in this case, harden SMB (disable if unnecessary, enforce account lockout, consider network segmentation so SMB isn't exposed to arbitrary hosts).
- [ ] Rebuild the host from a known-good image if there's any doubt about the completeness of eradication — "clean" and "confirmed clean" are different bars for a host that had this level of access.
- [ ] Validate Volume Shadow Copies / backup integrity is restored going forward (re-enable VSS, confirm scheduled backup jobs ran successfully post-incident).
- [ ] Re-enable monitoring and confirm the Wazuh agent is healthy and reporting before considering the host back in production.

### 🟢 Post-incident (lessons learned)
- Tighten the correlation rule further — e.g., also fire on `wbadmin delete catalog` and `wmic shadowcopy delete` as additional shadow-copy-deletion IOCs, not just `vssadmin`.
- Push MFA on any account with SMB/RDP access rather than relying on password complexity alone.
- Review why a weak, dictionary-adjacent password like `Password123!` was allowed to exist — a password policy that only checks complexity, not against known-breached password lists, will keep letting this happen.

---

## 📋 IOC Summary Table

| Indicator | Type | Context |
|---|---|---|
| `192.168.100.3` | Source IP | Attacker host (recon + brute force origin) |
| `labuser` | Account | Compromised via brute force, reused for persistence account |
| `Password123!` | Credential | Cracked SMB password — complexity-compliant but weak |
| `vssadmin delete shadows /all /quiet` | Command line | Shadow copy deletion — ransomware impact precursor |
| `reg add ...\Run /v Updater /t REG_SZ /d <base64>` | Command line | Registry-based persistence with obfuscated payload |
| `schtasks /create /sc once /tn TestTask` | Command line | Scheduled task persistence |
| `mshta.exe vbscript:msgbox(...)` | Command line | LOLBin script execution |
| `rundll32.exe shell32.dll,Control_RunDLL` | Command line | LOLBin defense evasion |

---

## 🧩 MITRE ATT&CK Coverage Map

| Tactic | Technique | ID |
|---|---|---|
| Reconnaissance | Network Service Discovery | T1046 |
| Credential Access | Brute Force | T1110 |
| Lateral Movement / Initial Access | Remote Desktop Protocol | T1021.001 |
| Discovery | Account Discovery: Local Account | T1087.001 |
| Discovery | System Information Discovery | T1082 |
| Persistence | Create Account: Local Account | T1136.001 |
| Persistence | Registry Run Keys / Startup Folder | T1547.001 |
| Persistence | Scheduled Task | T1053.005 |
| Defense Evasion | System Binary Proxy Execution: Rundll32 | T1218.011 |
| Defense Evasion | System Binary Proxy Execution: Mshta | T1218.005 |
| Impact | Inhibit System Recovery | T1490 |

---

*Written up as a training exercise — this guide reflects how I'd actually work a case like this, not a textbook answer.*
