# 🛡️ Living-off-the-Land Ransomware Precursor Detection Lab

![Wazuh](https://img.shields.io/badge/SIEM-Wazuh-3AA5DC?style=for-the-badge&logo=wazuh&logoColor=white)
![Kali](https://img.shields.io/badge/Attacker-Kali%20Linux-557C94?style=for-the-badge&logo=kalilinux&logoColor=white)
![Windows10](https://img.shields.io/badge/Victim-Windows%2010-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![Sysmon](https://img.shields.io/badge/Telemetry-Sysmon-6E40C9?style=for-the-badge)
![Docker](https://img.shields.io/badge/Deployment-Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![Status](https://img.shields.io/badge/Status-Complete-2ea44f?style=for-the-badge)

> A self-built detection lab where I played both sides — attacker and defender — against a Windows 10 host, then used Wazuh to hunt down what I did, write custom detection rules for the gaps, and document the whole thing like a real incident.

---

## 👋 Why I built this

I wanted proof I could do more than talk about SOC work — I wanted logs, alerts, and a rule I wrote myself sitting in a SIEM. So I stood up a small attacker/victim range, ran a realistic (if condensed) intrusion against my own Windows 10 box, and then sat on the blue team side hunting through Wazuh to reconstruct exactly what happened, minute by minute.

Everything in this repo is a real screenshot from that lab — timestamps, hit counts, rule IDs, all of it. Nothing here is staged text; it's what actually showed up on screen while I worked through it.

---

## 🗺️ Lab Topology

```
┌─────────────────────┐        ┌──────────────────────────┐
│   Kali Linux (VM)    │        │   Windows 10 Pro (VM)     │
│   192.168.100.3       │──────▶│   192.168.100.4            │
│                        │ SMB/  │                            │
│ • nmap                │ RDP   │ • Sysmon (custom config)   │
│ • Hydra               │       │ • Windows Event Logging     │
│ • Wazuh Manager        │       │ • Wazuh Agent (id: 002)     │
│   + Indexer + Dashboard│◀──────│   forwarding to manager    │
│   (Docker, single node)│ logs  │                            │
└─────────────────────┘        └──────────────────────────┘
```

Wazuh runs on the same Kali box as a Docker single-node stack (indexer + manager + dashboard) and the Windows 10 VM runs the Wazuh agent, forwarding Sysmon and Windows Security events back for analysis.

---

## 🧰 Tools & Skills Demonstrated

| Category | Tools / Techniques |
|---|---|
| **SIEM** | Wazuh (Manager, Indexer, Dashboard) — deployed via Docker Compose |
| **Endpoint Telemetry** | Sysmon, Windows Event Logs (Security, PowerShell) |
| **Offensive Tooling** | Nmap, Hydra (SMB brute force), native Windows LOLBins (`reg.exe`, `schtasks`, `rundll32`, `mshta`, `vssadmin`, `wmic`) |
| **Detection Engineering** | Custom Wazuh rules (XML), correlation rules, MITRE ATT&CK mapping |
| **Threat Hunting** | DQL / Kuery queries in Wazuh's Threat Hunting module, pivoting on command lines and registry activity |
| **Vulnerability Management** | Wazuh Vulnerability Detection module, CVE triage |
| **Compliance Mapping** | PCI DSS, GDPR, HIPAA, TSC control mapping via Wazuh rules |

---

## ⚔️ The Attack Story (short version)

I ran a compressed version of a real intrusion — recon, credential brute force, account creation for persistence, a couple of LOLBin defense-evasion tricks, and finally a shadow-copy deletion, which is the classic move ransomware makes right before it starts encrypting so victims can't just roll back.

| Stage | What I did | MITRE ATT&CK |
|---|---|---|
| 1. Recon | Full TCP port scan of the Windows host with Nmap | [T1046](https://attack.mitre.org/techniques/T1046/) Network Service Discovery |
| 2. Credential Access | Hydra brute force against SMB, cracked `labuser:Password123!` | [T1110](https://attack.mitre.org/techniques/T1110/) Brute Force |
| 3. Initial/Remote Access | Logged on remotely using the cracked credential (NTLM, RDP) | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) Remote Desktop Protocol |
| 4. Discovery | Enumerated local users, SIDs, files, processes (`Get-LocalUser`, `wmic useraccount`) | [T1087.001](https://attack.mitre.org/techniques/T1087/001/), [T1082](https://attack.mitre.org/techniques/T1082/) |
| 5. Persistence | Created a new local admin-capable account, added a `Run` registry key, dropped a scheduled task | [T1136.001](https://attack.mitre.org/techniques/T1136/001/), [T1547.001](https://attack.mitre.org/techniques/T1547/001/), [T1053.005](https://attack.mitre.org/techniques/T1053/005/) |
| 6. Defense Evasion | Abused `rundll32.exe` and `mshta.exe` (LOLBins) to run code and open Control Panel without a "normal" launcher | [T1218.011](https://attack.mitre.org/techniques/T1218/011/), [T1218.005](https://attack.mitre.org/techniques/T1218/005/) |
| 7. Impact Precursor | Ran `vssadmin delete shadows /all /quiet` — deletes Volume Shadow Copies, the step ransomware takes to kill local recovery options | [T1490](https://attack.mitre.org/techniques/T1490/) Inhibit System Recovery |

That last one is the headline finding. Wazuh's correlation engine actually caught it as part of a chain, not just a one-off alert — more on that below.

---

## 🔍 Detection Walkthrough

### 1. Environment stood up
Wazuh single-node stack came up clean via Docker Compose — indexer, manager, and dashboard containers all healthy.

`screenshots/01_environment_setup/01_wazuh_docker_deployment.png`

### 2. Recon & credential brute force (attacker side)
A full port scan against the Windows box turned up SMB (445), RPC (135), NetBIOS (139), and a couple of oddities worth a closer look. Hydra was then pointed at SMB with a small user/password list and, after working through a batch of invalid accounts, landed on a valid one.

- `screenshots/02_reconnaissance/03_nmap_portscan_hydra_start.png`
- `screenshots/03_initial_access_credential_access/05_hydra_smb_bruteforce_success.png`

### 3. Wazuh catches the logon
Once that cracked credential was used to log on remotely, Wazuh flagged it — NTLM auth pattern consistent with pass-the-hash, tagged as a possible RDP connection.

`screenshots/03_initial_access_credential_access/06_wazuh_detects_pass_the_hash_rdp.png`

### 4. Persistence — account, registry, scheduled task
From there I planted three separate footholds: a new local user (`labuser`), a `Run` key with a base64-looking payload string, and a scheduled task that fires a binary at a set time. Wazuh's own rule engine flagged the registry value on its own — "Value added to registry key has Base64-like pattern," level 10 — without me pointing it there.

- `screenshots/04_persistence/07_local_admin_account_created.png`
- `screenshots/04_persistence/08_wmic_account_sid_verification.png`
- `screenshots/04_persistence/09_registry_run_key_persistence.png`
- `screenshots/04_persistence/10_scheduled_task_persistence.png`

### 5. Defense evasion with LOLBins
`rundll32.exe shell32.dll,Control_RunDLL` popped Control Panel — a technique that's popular precisely because `rundll32` is a trusted, signed binary that almost nothing flags by default.

`screenshots/05_defense_evasion/11_rundll32_control_panel_lolbin.png`

### 6. The shadow copy deletion
This is the one that matters most. `vssadmin delete shadows /all /quiet` wipes every local restore point on the box — it's step one of basically every commodity ransomware playbook before the encryption routine kicks off.

`screenshots/06_impact_precursor/12_shadow_copy_deletion_vssadmin.png`

### 7. Threat hunting the aftermath
I went back into the Wazuh Threat Hunting module to reconstruct the timeline by hand — some queries came up empty (good to show, it's part of real hunting), others pinpointed the exact alert. The full 519-event timeline for the host ties everything together: logons, PowerShell scripting activity, the registry alert, and two separate firings of a correlation rule I wrote myself.

- `screenshots/07_detection_dashboard/13_wazuh_agent_overview_mitre_dashboard.png`
- `screenshots/07_detection_dashboard/14_threat_hunting_query_registry_noresult.png`
- `screenshots/07_detection_dashboard/15_dql_query_vssadmin_alert_hit.png`
- `screenshots/07_detection_dashboard/16_events_timeline_sysmon_dllhost_alert.png`
- `screenshots/07_detection_dashboard/17_full_attack_timeline_519_events.png`

### 8. Detection engineering
Wazuh ships a built-in Sysmon rule for suspicious `dllhost.exe` activity, mapped to GDPR/HIPAA/TSC compliance controls out of the box. But the alert I'm proudest of is one I wrote myself: **rule 100220**, a correlation rule that fires when multiple ransomware-precursor techniques (shadow copy deletion, scheduled task with encoded PowerShell, registry Run-key abuse, security tooling tampering) show up on the same host within a 5-minute window. That's not "one bad command" — that's a chain, and the rule treats it that way.

- `screenshots/08_detection_rules/18_builtin_rule_sysmon_dllhost_detail.png`
- `screenshots/08_detection_rules/19_custom_rule_ransomware_precursor_detail.png`
- `screenshots/08_detection_rules/20_custom_rule_xml_deployment_terminal.png`

### 9. Vulnerability management, bonus round
While I had the agent deployed, I let Wazuh's Vulnerability Detection module run against it too — 816 findings, mostly outdated Firefox packages, several rated Critical. Good reminder that unpatched browsers are still one of the easiest ways in. Also captured the Sysmon config driving all this telemetry, including the network-filter exclusion list.

- `screenshots/09_vulnerability_management/21_vulnerability_inventory_firefox_cves.png`
- `screenshots/09_vulnerability_management/22_sysmon_event_viewer_config.png`

---

## 📁 Repository Structure

```
Living-off-the-Land-Ransomware-Precursor-Detection-Lab/
│
├── README.md                     ← you are here
├── SOC_Response_Guide.md         ← attacker vs. defender playbook, stage by stage
│
└── screenshots/
    ├── 01_environment_setup/           # Wazuh + Docker stack going live
    ├── 02_reconnaissance/              # nmap, user/file enumeration
    ├── 03_initial_access_credential_access/  # Hydra brute force, pass-the-hash detection
    ├── 04_persistence/                 # new account, registry, scheduled task
    ├── 05_defense_evasion/             # LOLBin abuse
    ├── 06_impact_precursor/            # shadow copy deletion
    ├── 07_detection_dashboard/         # Wazuh dashboards & threat hunting
    ├── 08_detection_rules/             # built-in + custom Wazuh rules
    └── 09_vulnerability_management/    # CVE inventory, Sysmon config
```

I trimmed the raw screenshot dump down on purpose — the original set had a bunch of near-identical dashboard views (same event list, five minutes apart) and a couple of pure noise captures (a blank loading screen, 100+ rows of routine logoff events). Keeping those would just bury the parts that actually tell the story, so only the screenshots that add something new made the cut.

---

## 🎯 Key Findings

- **A cracked SMB credential led directly to a successful remote logon** — Wazuh's NTLM/pass-the-hash detection caught the reuse of that credential in real time.
- **Persistence was multi-layered**, not a single technique — new account, registry autorun, and a scheduled task were all planted, which is realistic attacker behavior (redundancy in case one gets cleaned up).
- **The most dangerous single action was the shadow copy deletion** — on its own it might look like routine admin cleanup; correlated against everything else that happened in the same five minutes, it's an unmistakable ransomware precursor.
- **Out-of-the-box rules caught some of this, but not the full picture** — writing a correlation rule that looks at technique clustering rather than individual events was what actually tied the story together.

---

## 📚 What I Took Away From This

- Correlation rules matter more than single-event alerts. A base64 registry value or a `vssadmin` call in isolation is low-signal; the same events clustered on one host in five minutes is a very different story.
- LOLBins are genuinely hard to catch with default rulesets — `rundll32` and `mshta` are signed, trusted, and everywhere. Detection has to lean on *behavior* (parent/child process chains, command-line arguments) rather than "is this binary bad."
- Threat hunting isn't just running the perfect query on the first try. Half my hunting screenshots are dead-end searches — that's normal and worth showing, not hiding.
- Vulnerability data and detection data tell complementary stories — the Firefox CVEs on this box are a reminder that even a well-monitored endpoint can still be an easy initial-access target if patching lags.

---

## 🔗 Related Document

For the full attacker-vs-defender breakdown — what the attacker does at each stage, how a SOC analyst should detect/investigate/contain/eradicate/recover, plus IOCs and detection logic — see **[SOC_Response_Guide.md](./SOC_Response_Guide.md)**.

---

*This lab was run entirely in isolated VirtualBox VMs on a private lab network (192.168.100.0/24). No production systems, third-party infrastructure, or real user data were involved.*
