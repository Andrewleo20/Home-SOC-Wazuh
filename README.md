# Home Security Operations Center (SOC) — Wazuh + Sysmon

## Overview
A home-lab SOC built from scratch using Wazuh and Sysmon to practice endpoint monitoring, log analysis, and threat detection. Simulated 5 attacker techniques with Atomic Red Team — spanning C2 traffic, credential dumping, UAC bypass, registry persistence, and process injection — and investigated each resulting Wazuh alert against the actual command-line evidence, not just the automated MITRE tag. Found a mix of accurate detections, mistagged/loose matches, and one critical-severity false positive, and documented the root cause and recommended fix for each.

---

## Architecture

```
[ Windows 10/11 VM ]                [ Wazuh Manager VM ]
  - Sysmon                            - Ubuntu 22.04
  - Wazuh Agent          ------>      - Wazuh Manager
  - Windows Event Logs                - Wazuh Indexer
                                       - Wazuh Dashboard

[ Kali Linux VM ] --------------------> (attacker, optional)

All VMs on shared Host-Only network: 192.168.56.0/24
```

*(Replace with your own diagram — draw.io, Excalidraw, or a screenshot of the VirtualBox network settings works fine.)*

| Component | OS | Role |
|---|---|---|
| Wazuh Manager | Ubuntu Server 22.04 | SIEM manager, indexer, dashboard |
| Windows Endpoint | Windows 10/11 | Monitored target — Sysmon + Wazuh agent |
| Attacker (optional) | Kali Linux | Simulated attack source |

---

## Setup Steps

- [ ] VirtualBox installed, Host-Only network configured
- [ ] Wazuh Manager installed (all-in-one script)
- [ ] Wazuh dashboard accessible, admin login confirmed
- [ ] Windows VM installed, static IP assigned
- [ ] Sysmon installed with SwiftOnSecurity/Olaf Hartong config
- [ ] Wazuh agent installed on Windows, registered with manager
- [ ] Agent shows "Active" in Wazuh dashboard
- [ ] Confirmed Sysmon + Windows Event Logs arriving in Wazuh (Threat Hunting view)
- [ ] (Optional) Kali VM set up for attack simulation

---

## Attack Simulations & Detections

For each technique: what you ran → what alert fired → the Wazuh rule ID → the ATT&CK mapping → your analyst notes (was it a true positive? what would you check next? any tuning needed?).

| # | Technique (ATT&CK ID) | Simulated Action (Atomic Red Team) | Detection / Rule ID | Match Quality | Analyst Notes | Full Alert |
|---|---|---|---|---|---|---|
| 1 | T1071.001 – Application Layer Protocol (Web) | `curl.exe` with spoofed/malicious User-Agent strings mimicking C2 beacon traffic | Rule 92032 – "Suspicious Windows cmd shell execution" (mapped T1059.003) | Loose | Wazuh caught the cmd→curl process chain but did not inspect the User-Agent value itself, so the actual T1071.001 signal (anomalous UA string) was missed. Detection gap: would need a custom rule matching on `commandLine` content, not just process lineage. | [alert_t1071_c2_traffic.json](alerts/alert_t1071_c2_traffic.json) |
| 2 | T1003.001 – OS Credential Dumping (LSASS) | Launched `nanodump.x64.exe` via PowerShell→cmd to dump LSASS memory | Rule 92052 – "Windows command prompt started by an abnormal process" (mapped T1059.003) | Loose | Only the generic "unusual shell spawn" pattern was caught — no dedicated Sysmon Event ID 10 (ProcessAccess/LSASS touch) alert fired. This is the most concerning gap: the actual credential-theft behavior went undetected by a specific rule. | [alert_t1003_credential_dumping.json](alerts/alert_t1003_credential_dumping.json) |
| 3 | T1053.005 / T1548.002 – Scheduled Task + UAC Bypass | Registry hijack (`mscfile` shell open command) + `schtasks` to trigger `eventvwr.msc` (EventViewerBypass UAC bypass) | Rule 92034 – "Discovery activity spawned via cmd shell execution" (mapped T1135 – Network Share Discovery) | Mismatched | MITRE tag was inaccurate — nothing here relates to network share discovery. Rule appears to fire on generic shell-execution patterns and default to a loosely related tag rather than reflecting actual UAC-bypass/persistence behavior. Shows automated MITRE mapping needs manual analyst verification. | [alert_t1053_uac_bypass.json](alerts/alert_t1053_uac_bypass.json) |
| 4 | T1112 – Modify Registry | `reg.exe` hijacked the `msedge.exe` App Paths key to launch `notepad.exe` instead | Rule 92041 – "Value added to registry key has Base64-like pattern" (mapped T1112, T1027) | **Strong** | Clean, accurate, high-confidence match (severity level 10). Wazuh correctly flagged both the registry modification (T1112) and the suspicious value pattern (T1027). This is the detection working as intended. | [alert_t1112_registry_hijack.json](alerts/alert_t1112_registry_hijack.json) |
| 5 | T1055 – Process Injection | Ran Atomic T1055 via PowerShell | Rule 92213 – "Executable file dropped in folder commonly used by malware" (mapped T1105 – Ingress Tool Transfer) | **False Positive** | Max-severity alert (level 15, mail-triggering) fired on PowerShell's own benign `__PSScriptPolicyTest*.ps1` housekeeping file in %TEMP%, not on the actual injection technique. Rule matches purely on path + extension without context, causing alert fatigue on normal PowerShell usage. Needs tuning (exclude this filename pattern). | [alert_t1055_false_positive.json](alerts/alert_t1055_false_positive.json) |

### Featured write-up: the false positive (T1055 test)

**Technique:** T1055 — Process Injection (Atomic Red Team)
**Action taken:** Ran `Invoke-AtomicTest T1055` from an elevated PowerShell session.
**Detection:** Wazuh fired a level-15 (critical, mail-triggering) alert — Rule 92213, "Executable file dropped in folder commonly used by malware," mapped to T1105 (Ingress Tool Transfer).
**Investigation notes:** On inspection, the flagged file was `__PSScriptPolicyTest_rslmtxvk.jaj.ps1` in `%TEMP%` — a temporary file PowerShell itself creates during script-execution-policy validation, not something the attack technique created. The rule matches on file path (`%TEMP%`) and extension pattern alone, with no allowlist for known-benign PowerShell artifacts. In a real SOC this rule would generate constant noise on any host running PowerShell scripts regularly, contributing to alert fatigue. Recommended fix: add an exclusion for the `__PSScriptPolicyTest*` filename pattern, or require additional corroborating signals (e.g., network connection, unusual parent process) before firing at critical severity.
**Full alert:** [alerts/alert_t1055_false_positive.json](alerts/alert_t1055_false_positive.json)

### Featured write-up: the clean detection (T1112 test)

**Technique:** T1112 — Modify Registry (App Paths Hijack)
**Action taken:** Ran `reg.exe add "HKLM\...\App Paths\msedge.exe" /d notepad.exe /f` via Atomic Red Team, redirecting the Edge App Path entry to launch Notepad instead.
**Detection:** Wazuh fired Rule 92041 at severity level 10, correctly mapped to both T1112 (Modify Registry) and T1027 (Obfuscated Files or Information).
**Investigation notes:** This is the cleanest result across all tests — Wazuh's rule inspected the actual registry value being written, not just the fact that a shell command ran, giving high analyst confidence this is a true positive worth escalating. Confirms the technique and highlights what a well-tuned detection rule looks like compared to the looser process-lineage-only rules seen elsewhere in this project.
**Full alert:** [alerts/alert_t1112_registry_hijack.json](alerts/alert_t1112_registry_hijack.json)

---

## Screenshots & Alert Data
- `screenshots/dashboard_overview.png` — Wazuh dashboard main view
- `screenshots/agent_active.png` — Windows endpoint showing Active status
- `alerts/` — full raw JSON for each of the 5 detected/investigated alerts (see table above for direct links)

---

## What I Learned

- Wazuh's built-in Sysmon detection rules are heavily weighted toward **process-lineage patterns** (e.g., "cmd spawned by an unusual parent") rather than **behavior-specific signals** (e.g., LSASS memory access, anomalous HTTP User-Agent values) — several real attack techniques (T1071.001, T1003.001) were only caught via this generic layer, not a technique-specific rule.
- Automated MITRE ATT&CK tagging in a SIEM is a starting point, not ground truth — one test (T1053.005/UAC bypass) was tagged with an unrelated technique (T1135, Network Share Discovery) purely because the underlying detection rule matches on execution pattern, not actual behavior. Manual verification against the raw command line is still required.
- High severity does not equal high confidence: the loudest alert in this project (level 15, mail-triggering) was a false positive caused by a rule that matches on file path/extension alone, with no allowlist for known-benign artifacts like PowerShell's own temp files.
- Debugged a real end-to-end data pipeline issue (agent registered as Active but Sysmon events weren't arriving) — root cause was a stale agent config that only resolved after a full service restart, reinforcing that "connected" status alone doesn't confirm data flow; you have to verify actual log ingestion.
- Building the lab from scratch (VirtualBox networking, Wazuh manager install, Sysmon config, agent enrollment, version-mismatch errors) gave hands-on experience with the kind of troubleshooting a SOC analyst does daily — reading logs, isolating variables, and not trusting the first plausible explanation.

## What I'd Improve / Add Next

- Add Suricata for network-based IDS alongside host-based Sysmon/Wazuh detection, to catch techniques like T1071.001 (C2 beaconing) at the network layer instead of relying solely on process-lineage rules that missed it here.
- Write a custom Wazuh rule to inspect `data.win.eventdata.commandLine` for anomalous User-Agent strings, closing the T1071.001 detection gap found in this project.
- Add an allowlist/exception for the `__PSScriptPolicyTest*.ps1` pattern in the "executable dropped in malware-common folder" rule to eliminate the false positive found during T1055 testing.
- Configure Wazuh active response (e.g., auto-isolate host or kill process on critical, high-confidence alerts).
- Add a second Windows endpoint to practice lateral movement detection (T1021) across hosts.
- Investigate why T1003.001 (LSASS/credential dumping via nanodump) didn't trigger a Sysmon Event ID 10 (ProcessAccess) alert — likely needs a specific correlation rule watching for processes accessing `lsass.exe` memory.

---

## Tools Used
Wazuh 4.9, Sysmon (SwiftOnSecurity config), VirtualBox, Windows 10/11, MITRE ATT&CK Navigator

---
