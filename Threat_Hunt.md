# 🔎 Threat Hunt Report — Suspicious "Ransom Note" in Azure Cyber Range
### Threat Hunt · Azure · Microsoft Defender for Endpoint · KQL · MITRE ATT&CK

---

## Executive Summary

During a threat hunting exercise in an Azure Cyber Range environment, a suspicious file consistent with a ransom note naming convention was detected propagating across the filesystem. The file creation event triggered **243 discrete write events within seconds**, spanning user directories, system paths, and package folders.

Rather than escalating immediately, a structured investigation was conducted to determine whether this represented an active ransomware compromise or a benign automated event. The hunt examined file telemetry, process lineage, kernel attribution, authentication activity, and persistence mechanisms before reaching a conclusion.

**Verdict:** The evidence points to a **cyber range simulation or automated security agent activity**, not an active breach. No encryption activity, lateral movement, or malicious persistence were identified.

---

## Environment

| Component | Detail |
|---|---|
| **Platform** | Microsoft Azure (Cyber Range) |
| **Detection Source** | Microsoft Defender for Endpoint (MDE) |
| **Query Language** | KQL (Kusto Query Language) |
| **Hunt Type** | Hypothesis-driven — Ransomware Indicator |
| **Scope** | Single endpoint — Windows Server |

---

## Hypothesis

> *"A ransom-style filename has been written across hundreds of directories in a short window. This could indicate active ransomware detonation or a simulation artifact. The goal is to determine which — and why."*

---

## MITRE ATT&CK Techniques Investigated

| Tactic | Technique | ID | Finding |
|---|---|---|---|
| Impact | Data Encrypted for Impact | T1486 | ❌ Not observed |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | ⚠️ Observed — attributed to Azure agents |
| Execution | Windows Command Shell | T1059.003 | ⚠️ Observed — attributed to Azure agents |
| Persistence | Boot or Logon Autostart Execution | T1547 | ❌ Not observed |
| Persistence | Scheduled Task/Job | T1053 | ❌ Not observed |
| Lateral Movement | Remote Services | T1021 | ❌ Not observed |
| Defense Evasion | Masquerading | T1036 | 🔍 Investigated — not confirmed |

---

## Investigation Walkthrough

### Step 1 — Confirm File Existence & Scope

The first step in any ransomware-adjacent investigation is straightforward: **does the file actually exist, and how far did it spread?**

```kql
DeviceFileEvents
| where FileName contains "README" or FileName contains "RECOVER" 
    or FileName contains "DECRYPT" or FileName contains "want_to_cry"
| summarize FileCount = count(), 
            DirectoryCount = dcount(FolderPath),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp)
    by FileName, DeviceName
| sort by FileCount desc
```

**Findings:**
- **243 file creation events** confirmed across the endpoint
- File was written to a wide range of directories — user home paths, system package folders, and application directories
- The breadth of the write pattern immediately suggested **automated propagation** rather than a human actor manually placing files

> A real ransomware actor dropping a ransom note would typically do so *after* encryption completes. The note appearing without accompanying mass rename or extension-change events was the first signal that something was off.

---

### Step 2 — Map the Timeline

With the scope confirmed, the next step was to establish a precise event timeline to understand how long the activity lasted and whether it correlated with any other suspicious events.

```kql
DeviceFileEvents
| where FileName contains "<want_to_cry.txt>"
| summarize 
    FirstEvent = min(Timestamp),
    LastEvent = max(Timestamp),
    TotalEvents = count(),
    UniqueDirectories = dcount(FolderPath)
    by DeviceName
| extend DurationSeconds = datetime_diff('second', LastEvent, FirstEvent)
```

**Findings:**
- All 243 write events occurred within an extremely **tight time window of a few seconds**
- Duration between first and last file write was consistent with **scripted or automated execution**, not manual file placement
- No gradual buildup — the writes were near-simultaneous across all directories

> The tight temporal clustering is a critical indicator. Humans don't create files in 200+ directories within seconds. Automation does.

---

### Step 3 — Identify the Initiating Process

With the timeline established, attention shifted to the process responsible for the writes. The `InitiatingProcessFileName` field in MDE telemetry reveals which process was attributed as the creator.

```kql
DeviceFileEvents
| where FileName contains "<want_to_cry.txt>"
| summarize EventCount = count() by InitiatingProcessFileName, 
    InitiatingProcessAccountName, InitiatingProcessCommandLine
| sort by EventCount desc
```

**Findings:**
- File writes were attributed to **`ntoskrnl.exe`** — the Windows kernel
- Kernel-attributed writes occur when the true originating process is **higher in the execution stack** or when a driver/kernel component is the proximate writer
- This is a known telemetry gap: when the kernel is listed as the initiator, the actual parent process must be discovered through process tree investigation

> `ntoskrnl.exe` as the initiating process is not inherently malicious — but it is a signal to look deeper. Ransomware can also use kernel-level writes to obscure attribution, so this required further investigation rather than immediate dismissal.

---

### Step 4 — Trace Process Execution

To find the real parent process, the investigation moved to process execution telemetry in the same time window as the file creation events.

```kql
DeviceProcessEvents
| where Timestamp between (datetime(<first_event>) .. datetime(<last_event>))
| where AccountName == "SYSTEM"
| project Timestamp, FileName, ProcessCommandLine, 
    InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName
| sort by Timestamp asc
```

**Findings:**
- **PowerShell (`powershell.exe`)** and **Command Shell (`cmd.exe`)** activity was present in the event window
- Both processes ran under the **SYSTEM account**
- Parent process chain traced back to **Azure Guest Agent (`WindowsAzureGuestAgent.exe`)** and **Microsoft Defender for Servers** extension processes
- No unsigned binaries, renamed executables, or off-path process locations were identified

> PowerShell running as SYSTEM is not unusual in Azure environments — the Guest Agent and Defender extensions routinely execute scripts under SYSTEM context for health checks, configuration enforcement, and security assessments. The key question is always: *who spawned it, and what did it do?*

---

### Step 5 — Look for Encryption Activity

The defining behavior of ransomware is not the ransom note — it is **mass file encryption**. This step searched for the hallmarks of active encryption: large-scale file renames, extension changes, and bulk file modification events.

```kql
// Look for mass file rename operations (extension swapping)
DeviceFileEvents
| where ActionType in ("FileRenamed", "FileModified")
| where Timestamp between (datetime(<hunt_window_start>) .. datetime(<hunt_window_end>))
| summarize RenameCount = count() by DeviceName, bin(Timestamp, 1m)
| where RenameCount > 50
| sort by RenameCount desc
```

```kql
// Look for novel file extensions appearing at scale
DeviceFileEvents
| where ActionType == "FileRenamed"
| extend NewExtension = tostring(split(FileName, ".")[-1])
| summarize count() by NewExtension
| where count_ > 20
| sort by count_ desc
```

**Findings:**
- **No mass file rename or extension-change operations** were observed
- No novel encrypted file extensions (e.g., `.locked`, `.enc`, `.crypted`) appeared in the environment
- File modification volume was within normal baseline parameters
- The ransom note file was written, but the payload it would accompany — the encrypted files — was absent

> This is the clearest indicator against active ransomware. Real ransomware encrypts first, then drops the note. A note without encryption is almost certainly either a simulation, a test artifact, or a failed detonation where the encryption stage never completed.

---

### Step 6 — Review Remote Access Activity

Ransomware operators frequently gain initial access via RDP or other remote services. Authentication logs and remote session activity were reviewed for anomalies.

```kql
DeviceLogonEvents
| where LogonType in ("RemoteInteractive", "Network")
| where Timestamp between (datetime(<hunt_window_start>) .. datetime(<hunt_window_end>))
| project Timestamp, AccountName, LogonType, RemoteIP, DeviceName
| sort by Timestamp asc
```

**Findings:**
- RDP session activity was present on the endpoint, consistent with normal administrative access to an Azure VM
- No suspicious process chains were spawned following remote logon events
- No logins from anomalous IP ranges, unusual geolocations, or outside of expected maintenance windows
- Session behavior matched typical administrative patterns with no post-login lateral movement

---

### Step 7 — Hunt for Persistence & Lateral Movement

Even if the immediate activity appeared benign, a thorough hunt checks whether the event was used as cover for establishing persistence or moving laterally.

```kql
// Registry run key modifications
DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any ("Run", "RunOnce", "Services", "Winlogon")
| where Timestamp between (datetime(<hunt_window_start>) .. datetime(<hunt_window_end>))
```

```kql
// New scheduled tasks
DeviceProcessEvents
| where FileName == "schtasks.exe"
| where ProcessCommandLine contains "/create"
| where Timestamp between (datetime(<hunt_window_start>) .. datetime(<hunt_window_end>))
```

```kql
// New service installation
DeviceEvents
| where ActionType == "ServiceInstalled"
| where Timestamp between (datetime(<hunt_window_start>) .. datetime(<hunt_window_end>))
```

**Findings:**
- No malicious registry run key modifications
- No unauthorized scheduled tasks created
- No new services installed outside of known Azure extension activity
- No SMB lateral movement, pass-the-hash, or credential dumping indicators (LSASS access patterns were normal)
- No outbound C2 communication patterns identified in network telemetry

---

## Evidence Summary

| Investigation Step | Observed | Verdict |
|---|---|---|
| Ransom-style file written to filesystem | ✅ Yes — 243 events | 🔍 Investigated |
| File spread across multiple directories | ✅ Yes — rapid propagation | ⚠️ Suspicious pattern |
| Activity in tight time window | ✅ Yes — seconds | ⚠️ Automation indicator |
| Kernel-attributed writes (ntoskrnl.exe) | ✅ Yes | ⚠️ Requires deeper investigation |
| PowerShell / cmd.exe under SYSTEM | ✅ Yes | ✅ Attributed to Azure agents |
| Parent process: Azure Guest Agent / Defender | ✅ Confirmed | ✅ Legitimate |
| Mass file encryption / extension changes | ❌ Not observed | ✅ No ransomware payload |
| Suspicious RDP / remote access | ❌ Not observed | ✅ Clean |
| Malicious persistence mechanisms | ❌ Not observed | ✅ Clean |
| Lateral movement indicators | ❌ Not observed | ✅ Clean |

---

## Conclusion

The totality of the evidence does not support an active ransomware compromise. The investigation identified:

1. **A ransom-style filename propagated via automation**, not manual placement
2. **Kernel-level write attribution**, explained by Azure infrastructure agents executing scripts under SYSTEM context
3. **PowerShell and cmd.exe activity tied to legitimate Azure Guest Agent and Defender for Servers processes** — not malicious executables
4. **Complete absence of encryption behavior** — the defining characteristic of ransomware was missing
5. **No persistence, lateral movement, or command-and-control indicators**

**Final Determination: Cyber range simulation artifact or automated security agent activity. No breach. No further escalation warranted.**

> This outcome highlights a critical threat hunting discipline: **pattern recognition must be paired with full evidence chain analysis before escalation**. A file named like a ransom note is alarming on its surface — but surface-level indicators alone do not constitute confirmation of compromise.

---

## Lessons Learned

**1. Temporal clustering is a powerful filter.**
When hundreds of events occur within seconds, automation is almost always the explanation. Human actors cannot operate at that speed and scale.

**2. Kernel process attribution requires a process tree pivot.**
`ntoskrnl.exe` as the initiating process is a telemetry gap — not a dead end. Always trace the parent chain before drawing conclusions.

**3. Ransomware without encryption is not ransomware.**
The ransom note is a social engineering artifact that follows the payload. Finding the note without finding the encrypted files is a strong indicator of simulation or failed execution.

**4. Azure environments generate significant SYSTEM-level PowerShell activity.**
The Azure Guest Agent, Defender for Servers, and Update Management extensions all execute scripts under SYSTEM. Understanding your environment's baseline is essential to avoid false positive fatigue.

**5. The absence of evidence is evidence.**
No persistence. No lateral movement. No encryption. No C2. Each negative finding adds weight to the benign conclusion — and each should be documented to support the determination.

---

## Tools & References

| Resource | Link |
|---|---|
| Microsoft Defender for Endpoint | [MDE Documentation](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/) |
| KQL Reference | [Kusto Query Language Docs](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/) |
| MITRE ATT&CK — T1486 | [Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/) |
| MITRE ATT&CK — T1059 | [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/) |
| Azure Guest Agent Overview | [Azure VM Agent Docs](https://learn.microsoft.com/en-us/azure/virtual-machines/extensions/agent-windows) |

---

*Threat hunting is the practice of proactively searching for threats that evade automated detection. This investigation demonstrates that not every alarming indicator leads to a confirmed breach — and that disciplined, evidence-based analysis is what separates effective hunters from reactive responders.*
