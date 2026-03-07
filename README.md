<!-- HEADER -->
<div align="center">

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ░█████╗░██╗░░░██╗██████╗░███████╗██████╗░  ██████╗░░█████╗░███╗░░██╗     ║
║   ██╔══██╗╚██╗░██╔╝██╔══██╗██╔════╝██╔══██╗  ██╔══██╗██╔══██╗████╗░██║     ║
║   ██║░░╚═╝░╚████╔╝░██████╦╝█████╗░░██████╔╝  ██████╔╝███████║██╔██╗██║     ║
║   ██║░░██╗░░╚██╔╝░░██╔══██╗██╔══╝░░██╔══██╗  ██╔══██╗██╔══██║██║╚████║     ║
║   ╚█████╔╝░░░██║░░░██████╦╝███████╗██║░░██║  ██║░░██║██║░░██║██║░╚███║     ║
║   ░╚════╝░░░░╚═╝░░░╚═════╝░╚══════╝╚═╝░░╚═╝  ╚═╝░░╚═╝╚═╝░░╚═╝╚═╝░░╚══╝     ║
║                                                                              ║
║          ── S E C U R I T Y  E N G I N E E R I N G  P O R T F O L I O ──   ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

<br>

[![Platform](https://img.shields.io/badge/PLATFORM-MICROSOFT_AZURE-0089D6?style=for-the-badge&logo=microsoftazure&logoColor=white)](.)
[![OS](https://img.shields.io/badge/OS-WINDOWS_11_%2F_SERVER-0078D4?style=for-the-badge&logo=windows11&logoColor=white)](.)
[![STIG](https://img.shields.io/badge/STIG-DoD_WN11_COMPLIANT-FF6B35?style=for-the-badge&logo=shield&logoColor=white)](.)
[![MDE](https://img.shields.io/badge/EDR-DEFENDER_FOR_ENDPOINT-00B4D8?style=for-the-badge&logo=microsoft&logoColor=white)](.)
[![Scanner](https://img.shields.io/badge/SCANNER-TENABLE_NESSUS-00C176?style=for-the-badge&logoColor=white)](.)
[![Language](https://img.shields.io/badge/LANGUAGE-KQL_%2F_POWERSHELL-5391FE?style=for-the-badge&logo=powershell&logoColor=white)](.)

<br>

> *A hands-on security engineering portfolio built across Azure Cyber Range infrastructure.*
> *Every investigation is real. Every script runs. Every metric is documented.*

<br>
</div>

---

## `> WHOAMI`

This is not a certificate collection. It is a **working cyber range** — a portfolio of real security engineering work conducted against live infrastructure in Microsoft Azure, documented with the rigor expected in enterprise and federal environments.

Three distinct disciplines are demonstrated here: **compliance hardening** enforced against DoD standards, **adversarial threat hunting** using structured hypothesis-driven methodology, and **enterprise vulnerability management** executed from zero policy to a 96.4% vulnerability reduction across a live Windows Server.

Designed to speak directly to security engineers, threat analysts, and hiring managers who want to see what someone actually builds — not what certifications they collected.

---

## `> LS -LA` · Repository Structure

```
cyber-range-portfolio/
│
├── 📁 STIG-Remediation/                    # DoD Windows 11 hardening scripts (10 controls)
│   ├── STIG-ID-WN11-CC-000197.ps1          #   Disable PowerShell 2.0
│   ├── STIG-ID-WN11-AC-000035.ps1          #   Account Lockout Threshold (≤3 attempts)
│   ├── STIG-ID-WN11-SO-000020.ps1          #   Disable Built-in Guest Account
│   ├── STIG-ID-WN11-AU-000505.ps1          #   Security Event Log ≥ 1 GB
│   ├── STIG-ID-WN11-CC-000070.ps1          #   Credential Guard — UEFI-locked VBS
│   ├── STIG-ID-WN11-CC-000038.ps1          #   AutoPlay Disabled — All Drive Types
│   ├── STIG-ID-WN11-CC-000326.ps1          #   WDigest Auth Disabled (anti-Mimikatz)
│   ├── STIG-ID-WN11-SO-000080.ps1          #   SMBv1 Disabled — EternalBlue mitigation
│   ├── STIG-ID-WN11-CC-000260.ps1          #   Windows Telemetry Restricted
│   └── STIG-ID-WN11-AU-000030.ps1          #   Audit Logon/Logoff Success + Failure
│
├── 📄 Threat_Hunt.md                       # Azure ransomware indicator investigation
│                                           #   KQL · MDE · MITRE ATT&CK · 7-step chain
│
└── 📄 Vulnerability-Management.md          # Full VM lifecycle: 111 → 4 vulns (−96.4%)
                                            #   Tenable · 4 scan cycles · policy to patch
```

---

## `> CAT MODULES`

<br>

### `[01]` · DoD STIG Hardening — Windows 11

Ten production-grade PowerShell remediation scripts covering the most exploited attack surfaces in modern Windows 11 environments. Each script implements the **DoD STIG benchmark** with a consistent 3-phase execution pattern — detect, remediate, and independently verify — with color-coded output and non-zero exit codes on failure for pipeline compatibility.

<div align="center">

| STIG ID | Control | CAT | Attack Vector Closed |
|:---|:---|:---:|:---|
| `WN11-CC-000197` | PowerShell 2.0 Disabled | II | AMSI / Script Block Logging bypass |
| `WN11-AC-000035` | Account Lockout ≤ 3 | II | Brute-force, password spray |
| `WN11-SO-000020` | Guest Account Disabled | II | Anonymous access, lateral movement |
| `WN11-AU-000505` | Security Log ≥ 1 GB | II | Log overflow, forensic evidence destruction |
| `WN11-CC-000070` | Credential Guard (UEFI) | II | Pass-the-Hash, LSASS credential theft |
| `WN11-CC-000038` | AutoPlay Disabled | II | USB drop, removable media execution |
| `WN11-CC-000326` | WDigest Disabled | II | Mimikatz cleartext credential harvest |
| `WN11-SO-000080` | SMBv1 Disabled | I | EternalBlue, WannaCry, NotPetya |
| `WN11-CC-000260` | Telemetry Restricted | II | Data exfiltration surface exposure |
| `WN11-AU-000030` | Logon Audit S+F | II | Auth attack detection, IR visibility |

</div>

**Script Architecture** — Every script follows a consistent 3-phase execution model:

```powershell
# ── PHASE 1 · DETECT ──────────────────────────────────────────────────────
$currentValue = Get-ItemProperty -Path $registryPath -Name $valueName
Write-Host "[INFO] Current value: $currentValue"

# ── PHASE 2 · REMEDIATE ───────────────────────────────────────────────────
Set-ItemProperty -Path $registryPath -Name $valueName -Value $required -Type DWord
Write-Host "[REMEDIATE] Applying control..."

# ── PHASE 3 · VERIFY ──────────────────────────────────────────────────────
$newValue = Get-ItemProperty -Path $registryPath -Name $valueName
if ($newValue -eq $required) { Write-Host "[SUCCESS]" -ForegroundColor Green }
else { Write-Host "[ERROR] Manual review required." -ForegroundColor Red; exit 1 }
```

```
[PASS]       Control already compliant — no change made
[REMEDIATE]  Non-compliant value detected — applying fix
[SUCCESS]    Remediation applied and independently verified
[ERROR]      Change failed — exits with code 1 for pipeline visibility
[INFO]       OS detection, current values, and Windows 11-specific context
```

---

### `[02]` · Threat Hunt — Azure Ransomware Indicator Investigation

**`Threat_Hunt.md`**

A complete evidence-driven adversarial investigation conducted inside a **Microsoft Azure Cyber Range** using **Microsoft Defender for Endpoint** and **KQL**. A suspicious file consistent with ransom note naming conventions (`want_to_cry.txt`) was detected propagating across an endpoint — **243 discrete write events within seconds**, spanning user directories, system paths, and package folders.

Rather than escalate immediately, a structured 7-step investigation chain was executed.

#### Investigation Chain

```
STEP 1  Confirm file existence and propagation scope
        └─ 243 write events confirmed · broad directory spread · automated pattern flagged

STEP 2  Map the precise event timeline
        └─ All 243 events within seconds · temporal clustering rules out human actor

STEP 3  Identify the initiating process
        └─ Attributed to ntoskrnl.exe (kernel) · telemetry gap · pivot required

STEP 4  Trace parent process execution chain
        └─ PowerShell + cmd.exe under SYSTEM · parent: Azure Guest Agent / Defender for Servers

STEP 5  Hunt for mass encryption activity
        └─ Zero FileRenamed events · zero novel extensions · no encrypted payload present

STEP 6  Review remote access and authentication logs
        └─ RDP activity present · no anomalous IPs · no suspicious post-logon process chains

STEP 7  Hunt persistence and lateral movement indicators
        └─ No run key writes · no scheduled tasks · no new services · no C2 network patterns
```

#### KQL Queries Deployed

```kql
// Scope the propagation
DeviceFileEvents
| where FileName contains "README" or FileName contains "RECOVER"
    or FileName contains "DECRYPT" or FileName contains "want_to_cry.txt"
| summarize FileCount = count(), DirectoryCount = dcount(FolderPath),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
    by FileName, DeviceName

// Temporal clustering — duration of write activity
DeviceFileEvents
| where FileName contains "want_to_cry.txt"
| summarize FirstEvent = min(Timestamp), LastEvent = max(Timestamp),
            TotalEvents = count(), UniqueDirectories = dcount(FolderPath)
    by DeviceName
| extend DurationSeconds = datetime_diff('second', LastEvent, FirstEvent)

// Identify the initiating process
DeviceFileEvents
| where FileName contains "want_to_cry.txt"
| summarize EventCount = count()
    by InitiatingProcessFileName, InitiatingProcessAccountName, InitiatingProcessCommandLine

// Hunt for mass file rename (encryption hallmark)
DeviceFileEvents
| where ActionType in ("FileRenamed", "FileModified")
| summarize RenameCount = count() by DeviceName, bin(Timestamp, 1m)
| where RenameCount > 50

// Persistence: registry run key modifications
DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any ("Run", "RunOnce", "Services", "Winlogon")
```

#### MITRE ATT&CK Coverage

| Tactic | Technique | ID | Finding |
|:---|:---|:---|:---|
| Impact | Data Encrypted for Impact | `T1486` | ❌ Not observed — no encryption payload |
| Execution | PowerShell | `T1059.001` | ⚠️ Present — attributed to Azure agents |
| Execution | Windows Command Shell | `T1059.003` | ⚠️ Present — attributed to Azure agents |
| Persistence | Boot/Logon Autostart | `T1547` | ❌ Not observed |
| Persistence | Scheduled Task/Job | `T1053` | ❌ Not observed |
| Lateral Movement | Remote Services | `T1021` | ❌ Not observed |
| Defense Evasion | Masquerading | `T1036` | 🔍 Investigated — not confirmed |

**Verdict:** `CYBER RANGE SIMULATION ARTIFACT` — Ransom note propagated by Azure Guest Agent and Defender for Servers extension processes running under SYSTEM context. No encryption payload. No persistence. No lateral movement. No escalation warranted.

> *"Ransomware without encryption is not ransomware. The note is a social engineering artifact that follows the payload — finding the note without finding encrypted files is a strong indicator of simulation or failed execution."*

---

### `[03]` · Vulnerability Management Program — 111 → 4 Vulnerabilities

**`Vulnerability-Management.md`**

A full-cycle enterprise vulnerability management engagement against a live Windows Server (`matrix-vm-server`) in Azure — executed from **zero existing policy** through four structured remediation rounds, with documented scan-over-scan delta metrics and authenticated Tenable Nessus data at every stage.

**Inception state:** No scanning policy. No existing remediation workflow. Server running outdated third-party software, misconfigured accounts, deprecated protocols, and unpatched OS components.

#### Program Lifecycle

```
PHASE 1 · Policy Development
          └─ Drafted VM policy: scope, roles, SLA windows, escalation procedures
          └─ Stakeholder session with server team · Critical SLA negotiated: 48hr → 7 days
          └─ Senior leadership sign-off obtained · policy becomes governing document

PHASE 2 · Scan Authorization & CAB Approval
          └─ Scope agreement: single server initially to assess scan resource impact
          └─ Just-in-time AD credentials provisioned for authenticated scanning
          └─ CAB approval obtained for all four remediation rounds before changes executed

PHASE 3 · Baseline Credentialed Scan (Scan 1)
          └─ 111 total vulnerabilities · Critical: 51 · High: 25 · Medium: 33 · Low: 2
          └─ Key findings: Wireshark EOL · Firefox years-unpatched · Java CPU backlog
          └─ Guest account in privileged group · TLS 1.0/1.1 active · SMB signing off

PHASE 4 · Prioritized Remediation (4 Rounds)
          └─ Ordered by: impact per unit of remediation complexity
          └─ Non-disruptive changes first · reboot-required patching last

PHASE 5 · Validation & Maintenance Mode
          └─ 4 residual findings tracked to next CAB cycle with assigned ownership
          └─ Ongoing cadence: weekly scans (critical assets) · monthly (standard servers)
```

#### Scan-Over-Scan Results

```
                          CRIT    HIGH    MED    LOW    TOTAL
                         ──────  ──────  ─────  ─────  ──────
Scan 1 · Baseline           51      25     33      2     111
Scan 2 · 3rd-Party Removed  24       8      9      2      43    ─61.3%
Scan 4 · Final               0       1      2      1       4    ─96.4%
```

```
111  ██████████████████████████████████████████████████████  Baseline
 43  █████████████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  Post 3rd-Party Removal (−61%)
  4  ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  Final (−96.4%)
```

#### Remediation Rounds

**Round 1 — Third-Party Software Removal** `−68 vulnerabilities · −61.3%`

Wireshark 2.2.x (End-of-Life, multiple DoS CVEs via Plugins 56710, 213824, and 16 others), Mozilla Firefox running so far behind that plugins span 172515 through 299865 — years of unpatched critical CVEs — and Oracle Java SE with unresolved CPU advisories from April 2024, July 2025, and January 2026. Software hygiene alone accounted for the majority of the total reduction.

**Round 2 — Guest Account Hardening** `Plugin 10907 resolved`

Guest account found as a member of a local group with elevated privileges (Plugin 10907) — a misconfiguration enabling access escalation from unauthenticated sessions. Removed via PowerShell, verified post-change.

**Round 3 — Protocol & TLS Hardening** `Plugins 104743, 157288, 51192, 57582 resolved`

Disabled TLS 1.0 and TLS 1.1 via SCHANNEL registry keys. Replaced self-signed SSL certificate. Enforced SMB signing to block NTLM relay (Plugin 57608). Applied WinVerifyTrust `EnableCertPaddingCheck` mitigation for CVE-2013-3900 (Plugin 166555). All changes deployed through the CAB-approved window with rollback scripts pre-tested.

**Round 4 — Windows OS Patching** `Remaining CVEs closed`

Windows Update service had been manually disabled on the server. Re-enabled the `wuauserv` service, applied all pending security patches, and rebooted during the approved maintenance window. Patch compliance verified post-restart via a final authenticated scan.

#### Final Results

| Severity | Initial | Final | Reduction |
|:---|:---:|:---:|:---|
| 🔴 Critical | 51 | **0** | ⬇️ `−100%` ✅ |
| 🟠 High | 25 | **1** | ⬇️ `−96%` |
| 🟡 Medium | 33 | **2** | ⬇️ `−93.9%` |
| 🔵 Low | 2 | **1** | ⬇️ `−50%` |
| **Total** | **111** | **4** | ⬇️ **`−96.4%`** |

**4 residual findings** are tracked in the remediation backlog with assigned owners and target resolution dates aligned to policy SLA requirements.

---

## `> NMAP -sV` · Skills Demonstrated

```
COMPLIANCE & HARDENING ─────────────────────────────────────────────────────
  [████████████████████]  DoD STIG Implementation — Windows 11 (10 controls)
  [████████████████████]  PowerShell Remediation Scripting with Verification
  [██████████████████░░]  NIST SP 800-53 / CIS Benchmark Alignment

THREAT DETECTION & HUNTING ─────────────────────────────────────────────────
  [████████████████████]  MITRE ATT&CK (T1486, T1059, T1547, T1053, T1021, T1036)
  [████████████████████]  KQL — Microsoft Defender for Endpoint Telemetry
  [████████████████████]  Hypothesis-Driven, Evidence-Chained Hunt Methodology
  [██████████████████░░]  Process Tree Analysis & Kernel Attribution Pivoting

VULNERABILITY MANAGEMENT ───────────────────────────────────────────────────
  [████████████████████]  Tenable Nessus — Credentialed Authenticated Scanning
  [████████████████████]  CVSS v3.1 Risk Prioritization & Remediation Sequencing
  [████████████████████]  Enterprise VM Lifecycle (Policy → CAB → Patch → Verify)
  [██████████████████░░]  SLA Tracking, Stakeholder Communication, Audit Reporting

TOOLING & PLATFORMS ─────────────────────────────────────────────────────────
  [████████████████████]  Microsoft Azure (Cyber Range Infrastructure)
  [████████████████████]  Microsoft Defender for Endpoint (MDE)
  [████████████████████]  Tenable Vulnerability Management
  [████████████████░░░░]  Microsoft Sentinel / Log Analytics
```

---

## `> GREP -R "FRAMEWORKS"` · Standards & Mappings

<div align="center">

| Framework | Application in This Portfolio |
|:---|:---|
| **DISA STIG** (Windows 11) | Primary standard for all 10 PS1 hardening scripts |
| **MITRE ATT&CK** | TTP coverage mapped to every threat hunt step |
| **NIST SP 800-53** | Control families cross-referenced in VM policy |
| **NIST SP 800-40** | Patch management process and SLA structure |
| **CVSS v3.1** | Severity scoring for all Tenable scan findings |
| **CIS Controls** | Software lifecycle and access control benchmarks |

</div>

---

## `> SYSTEMCTL STATUS` · Environment

```yaml
Cyber Range Infrastructure:
  Cloud Platform:    Microsoft Azure
  EDR:               Microsoft Defender for Endpoint
  SIEM / Hunting:    Microsoft Sentinel + Log Analytics (KQL)
  Vuln Scanner:      Tenable Vulnerability Management (Credentialed)
  Scan Target:       Windows Server (matrix-vm-server)
  Hardening Target:  Windows 11 Enterprise
  Shell:             PowerShell 5.1 + PowerShell 7.x
  Query Language:    KQL (Kusto Query Language)
  Change Process:    CAB-gated remediation with rollback documentation
  Policy Basis:      DISA STIG · NIST SP 800-53/40 · Formal VM Policy
```

---

## `> CAT /ETC/ABOUT` · On Building This

Every hiring manager eventually asks the same question:

> *"Walk me through something you actually built."*

This portfolio is the answer. Not a lab walkthrough copied from a tutorial. Not a badge earned by clicking through a course module. Everything documented here was researched from primary sources — **DISA STIG Viewer, MITRE ATT&CK, NIST publications, Microsoft Learn, and Tenable plugin documentation** — and executed against real systems in Azure.

The threat hunt started with a genuine alert. The vulnerability program started with a server carrying **51 critical vulnerabilities and zero existing scanning policy**. The STIG scripts were written, tested, broken, and fixed until they produced verified output on real Windows 11 machines.

The work reflects how security is actually done in enterprise and federal environments: structured process, documented evidence, CAB-approved change control, and the discipline to distinguish a confirmed breach from a false positive — before escalating.

---

## `> CONNECT`

<div align="center">

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Let's_Connect-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white)](https://linkedin.com/in/YOURPROFILE)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/YOURUSERNAME)
[![Email](https://img.shields.io/badge/Email-Reach_Out-EA4335?style=for-the-badge&logo=gmail&logoColor=white)](mailto:YOUREMAIL@domain.com)

<br>

```
"The goal of a security portfolio is not to list tools.
 It is to demonstrate how you reason under uncertainty."
```

<br>

---

<sub>All scripts tested on Windows 11 Enterprise · All KQL queries executed in Microsoft Defender for Endpoint · All vulnerability data sourced from authenticated Tenable Nessus scans against matrix-vm-server · All MITRE ATT&CK mappings sourced from attack.mitre.org</sub>

</div>
