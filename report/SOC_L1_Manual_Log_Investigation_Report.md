# SOC L1 Manual Log Investigation Report — Account "sanket"

## 1. Investigation Summary

- **Investigation Title:** Manual Log Investigation — Possible Compromise of User Account "sanket"
- **Date/Period Covered:** 2026-09-18, 08:42:11 – 09:15:19 (all timestamps as recorded in the supplied logs)
- **Systems Investigated:** WIN-SRV01 (Windows), WIN-SRV02 (Windows), linux-srv01 (Linux)
- **Windows Log Sources Analyzed:** Windows Security Event Log (Events 4624, 4625, 4672, 4688), Windows PowerShell Log (Event 4104)
- **Linux Log Sources Analyzed:** Linux Authentication Log (`auth.log` — sshd, sudo), Linux System Log (`syslog` — systemd, kernel audit, CRON)
- **User Account Investigated:** `sanket` (also observed: `admin`, reviewed for correlation purposes only)
- **Initial Complaint:** User account may have been compromised.
- **Overall Finding:** The supplied logs show a correlated pattern of brute-force authentication followed by successful login, from the same external source IP, against the same account, on two different platforms (Windows RDP and Linux SSH) within roughly 90 seconds of each other — followed immediately by discovery/reconnaissance command execution on both systems and a subsequent login to a second Windows host.

> **Initial Assessment: Confirmed Compromise**

---

## 2. Key Findings

| # | Finding | Evidence / Log Entry | Log Source | Timestamp | Evidence Confidence |
|---|---|---|---|---|---|
| 1 | Repeated failed SSH logins for `sanket` from external IP `185.220.101.44`, immediately followed by a successful login | `Failed password for sanket from 185.220.101.44 port 51221 ssh2` (×3), then `Accepted password for sanket from 185.220.101.44 port 51221 ssh2` | Linux auth.log | 09:01:42 – 09:02:06 | High |
| 2 | Repeated failed RDP logins for `sanket` from the **same** external IP `185.220.101.44`, immediately followed by a successful login, ~77 seconds after the Linux success | `EventCode=4625`, `LogonType=10`, `SourceNetworkAddress=185.220.101.44` (×2), then `EventCode=4624`, `LogonType=10`, same source IP | Windows Security Event Log | 09:03:17 – 09:03:29 | High |
| 3 | Special privilege (`SeDebugPrivilege`) assigned to `sanket` immediately after the successful RDP logon | `EventCode=4672`, `SubjectUserName=sanket`, `PrivilegeList=SeDebugPrivilege` | Windows Security Event Log | 09:04:02 | Medium |
| 4 | Immediately after logon, `sanket` executed a chain of discovery commands on WIN-SRV01: `whoami`, `Get-Process`, `net user`, `ipconfig /all`, `netstat -ano` | `EventCode=4688` entries with corresponding `CommandLine` values | Windows Security Event Log / PowerShell log | 09:05:14 – 09:12:45 | High |
| 5 | Immediately after logon, `sanket` (via `sudo`) executed discovery commands on linux-srv01: `id`, `cat /etc/passwd`, `ip addr`, `ss -tulpn` | `sudo: sanket : ... USER=root ; COMMAND=...` entries | Linux auth.log | 09:02:25 – 09:04:17 | High |
| 6 | `sanket` authenticated to a **second** host, WIN-SRV02, via network logon shortly after the WIN-SRV01 activity | `EventCode=4624`, `LogonType=3`, `SourceNetworkAddress=10.10.20.15`, `AuthenticationPackage=NTLM` | Windows Security Event Log | 09:15:19 | Medium |
| 7 | Separate `admin` account activity (SSH public-key login, single `sudo` status check) from internal IP `10.10.20.5` | `Accepted publickey for admin from 10.10.20.5`; `sudo: admin ... COMMAND=/usr/bin/systemctl status ssh` | Linux auth.log | 09:06:33 – 09:07:11 | Low (as a compromise indicator) — appears to be routine administrative activity |

---

## 3. Chronological Investigation Timeline

| Time | Host | User | Source IP | Event | Log Source | Event ID/Type | Significance | Confidence |
|---|---|---|---|---|---|---|---|---|
| 08:42:11 | WIN-SRV01 | sanket | — (local) | Successful interactive logon (Type 2), subject=SYSTEM | Windows Security | 4624 | Baseline/normal-appearing local or service-driven logon; no external IP | Not Established (as suspicious) |
| 09:01:42 | linux-srv01 | sanket | 185.220.101.44 | Failed SSH password | Linux auth.log | sshd | Start of brute-force pattern | High |
| 09:01:47 | linux-srv01 | sanket | 185.220.101.44 | Failed SSH password | Linux auth.log | sshd | Continued brute-force | High |
| 09:01:54 | linux-srv01 | sanket | 185.220.101.44 | Failed SSH password | Linux auth.log | sshd | Continued brute-force | High |
| 09:02:06 | linux-srv01 | sanket | 185.220.101.44 | **Successful** SSH login | Linux auth.log | sshd | Successful auth after 3 failures from same IP | High |
| 09:02:07 | linux-srv01 | sanket | 185.220.101.44 | Session opened (uid=1001) | Linux auth.log | pam_unix | Session establishment | High |
| 09:02:08 | linux-srv01 | sanket | — | Session 41 started | Linux syslog | systemd | Corroborates session start | High |
| 09:02:25 | linux-srv01 | sanket | — | `sudo id` | Linux auth.log | sudo | Discovery: identity check as root | High |
| 09:03:01 | linux-srv01 | sanket | — | `sudo cat /etc/passwd` | Linux auth.log | sudo | Discovery: local account enumeration | High |
| 09:03:17 | WIN-SRV01 | sanket | 185.220.101.44 | Failed RDP logon | Windows Security | 4625 | Start of brute-force pattern on second platform, same IP/user | High |
| 09:03:21 | WIN-SRV01 | sanket | 185.220.101.44 | Failed RDP logon | Windows Security | 4625 | Continued brute-force | High |
| 09:03:29 | WIN-SRV01 | sanket | 185.220.101.44 | **Successful** RDP logon (Type 10) | Windows Security | 4624 | Successful auth after 2 failures, same IP as Linux activity 77s earlier | High |
| 09:03:42 | linux-srv01 | sanket | — | `sudo ip addr` | Linux auth.log | sudo | Discovery: network configuration | High |
| 09:04:02 | WIN-SRV01 | sanket | — | Special privilege assigned (SeDebugPrivilege) | Windows Security | 4672 | Elevated privilege associated with new RDP logon | Medium |
| 09:04:17 | linux-srv01 | sanket | — | `sudo ss -tulpn` | Linux auth.log | sudo | Discovery: listening ports/services | High |
| 09:05:11 | linux-srv01 | sanket | 185.220.101.44 | `USER_LOGIN` audit event | Linux syslog | kernel audit | Corroborates SSH login source IP | High |
| 09:05:14 | WIN-SRV01 | sanket | — | `cmd.exe /c whoami` | Windows Security | 4688 | Discovery: identity check | High |
| 09:05:31 | WIN-SRV01 | sanket | — | PowerShell scriptblock: `Get-Process` | PowerShell log | 4104 | Discovery: running processes | High |
| 09:05:32 | WIN-SRV01 | sanket | — | `powershell.exe -ExecutionPolicy Bypass -Command "Get-Process"` | Windows Security | 4688 | Execution policy bypass used for discovery command | Medium |
| 09:06:01 | WIN-SRV01 | sanket | — | PowerShell scriptblock: `Get-Service` | PowerShell log | 4104 | Discovery: services | High |
| 09:06:32 | WIN-SRV01 | sanket | — | PowerShell scriptblock: `Get-LocalUser` | PowerShell log | 4104 | Discovery: local accounts | High |
| 09:06:33 | linux-srv01 | admin | 10.10.20.5 | Successful SSH public-key login | Linux auth.log | sshd | Separate account/internal IP; appears routine | Low |
| 09:07:11 | linux-srv01 | admin | — | `sudo systemctl status ssh` | Linux auth.log | sudo | Routine service status check | Low |
| 09:07:44 | WIN-SRV01 | sanket | — | `cmd.exe /c net user` | Windows Security | 4688 | Discovery: local user accounts | High |
| 09:08:03 | WIN-SRV01 | sanket | — | `cmd.exe /c ipconfig /all` | Windows Security | 4688 | Discovery: network configuration | High |
| 09:10:24 | linux-srv01 | admin | — | Session 42 started | Linux syslog | systemd | Routine admin session | Low |
| 09:12:38 | linux-srv01 | root | — | CRON systemd-tmpfiles clean | Linux syslog | CRON | Routine scheduled maintenance task | Not Established (as suspicious) |
| 09:12:45 | WIN-SRV01 | sanket | — | `cmd.exe /c netstat -ano` | Windows Security | 4688 | Discovery: active network connections | High |
| 09:15:19 | WIN-SRV02 | sanket | 10.10.20.15 | Successful network logon (Type 3, NTLM) | Windows Security | 4624 | Same account accessing a second host shortly after recon on WIN-SRV01 | Medium |

**Coherence of sequence:** The events between 09:01:42 and 09:15:19 form a coherent, chronologically consistent sequence: brute-force credential access on two platforms from the same external IP within ~90 seconds of each other, followed by near-identical discovery activity on both platforms, followed by access to a second host under the same username. The `admin` account activity does not fit this sequence and is treated separately.

---

## 4. Authentication Analysis

- **Failed → Successful pattern (Linux):** Three failed SSH password attempts for `sanket` from `185.220.101.44` (09:01:42–09:01:54), followed by a successful login from the same IP/port at 09:02:06. This is a classic brute-force-then-success pattern. **Confidence: High.**
- **Failed → Successful pattern (Windows):** Two failed RDP logon attempts for `sanket` from `185.220.101.44` (09:03:17–09:03:21), followed by a successful RDP logon from the same IP at 09:03:29. **Confidence: High.**
- **Cross-platform timing:** The Linux success (09:02:06) and the Windows RDP success (09:03:29) occurred approximately 83 seconds apart, from the identical source IP and against the identical username, on two unrelated platforms. This strongly suggests a single actor in possession of valid or guessed credentials for the `sanket` account attempting access wherever it was valid. **Confidence: High.**
- **Logon types:** Linux access was via SSH (password auth); Windows access was via RDP (`LogonType=10`, Negotiate). Both are remote, interactive-style access methods reachable from external networks — consistent with externally-initiated access rather than local administration.
- **Source IP `185.220.101.44`:** This address is not identified anywhere else in the logs as a previously-used or "normal" source for `sanket`; no earlier baseline logons from this IP are present in the supplied evidence, so its use cannot be confirmed as anomalous relative to a historical baseline — but the accompanying brute-force pattern on two platforms is itself sufficient evidence of suspicious authentication activity. **Confidence: High (suspicious), Not Established (as definitively "never used before" absent a longer baseline).**
- **Cross-system authentication:** `sanket` authenticated to WIN-SRV02 at 09:15:19 from internal IP `10.10.20.15`, shortly after the WIN-SRV01 activity concluded. The logs do not confirm that `10.10.20.15` is the IP address of WIN-SRV01 itself (no IP is recorded for WIN-SRV01 in the supplied Windows logs), so this cannot be stated as definitively originating from the already-compromised host. **Confidence: Medium** that this represents follow-on/lateral activity by the same actor, based on timing and shared username.
- **`admin` account authentication:** A single successful public-key SSH login from `10.10.20.5`, followed by one `sudo` status check. No failed attempts, no discovery-style command chain. This pattern is inconsistent with the `sanket` activity and, on its own, does not indicate compromise. **Confidence: Low** as an indicator of anything suspicious.

---

## 5. Privilege Escalation Analysis

- **Windows (Event 4672):** `SeDebugPrivilege` was assigned to `sanket` at 09:04:02, immediately following the successful RDP logon. `SeDebugPrivilege` is a sensitive privilege often associated with debugging/inspecting other processes and is frequently referenced in credential-access and process-injection tooling. However, `4672` events are commonly generated for a variety of standard elevated logon scenarios and do not, by themselves, prove malicious use of the privilege — no subsequent 4688 event in the supplied logs shows a process that explicitly leveraged this privilege for credential dumping or injection. **Confidence: Medium** — notable and worth flagging, but not conclusive proof of privilege abuse.
- **Linux (`sudo`):** `sanket` used `sudo` four times (`id`, `cat /etc/passwd`, `ip addr`, `ss -tulpn`), each escalating to `USER=root`. This confirms the account had `sudo` rights and exercised them for reconnaissance-style commands rather than for a clear administrative task. **Confidence: High** that root-level commands were executed; **Medium** on whether this represents unauthorized privilege *use* versus a legitimately privileged user exploring their own access (context is inconclusive without a ticket/change record).
- **`admin` account:** Used `sudo` once for a benign status check (`systemctl status ssh`) — consistent with routine administration. **Confidence: Low** as an escalation concern.

---

## 6. Process and Command Analysis (Windows)

| Command | Purpose | Investigative Relevance |
|---|---|---|
| `whoami` | Identity check | Common first action after gaining a new session; used by both administrators and attackers to confirm current user/context. |
| `Get-Process` (PowerShell) | List running processes | Discovery — used to identify security tooling, other users' processes, or targets for further action. |
| `net user` | Enumerate local user accounts | Account discovery — frequently used by attackers to identify other accounts for lateral movement or persistence. |
| `ipconfig /all` | Display network configuration | Network discovery — used to understand the host's position on the network. |
| `netstat -ano` | List active connections/listening ports with PIDs | Network discovery — used to identify open connections, other sessions, or monitoring tools. |
| `Get-Service` (PowerShell) | List installed/running services | Discovery — can reveal security agents (EDR/AV) or misconfigured services. |
| `Get-LocalUser` (PowerShell) | List local user accounts (PowerShell equivalent of `net user`) | Account discovery, redundant with `net user` — repetition across two tools may indicate methodical enumeration rather than a single ad hoc check. |

**Assessment:** No single command in this list is inherently malicious — every one of them is also used routinely by legitimate administrators. What makes this sequence suspicious is the **combination and timing**: a rapid, systematic chain of identity/user/process/service/network discovery commands executed within minutes of a brute-force-then-success remote logon, using both `cmd.exe` and PowerShell (with `-ExecutionPolicy Bypass`, itself a mild anomaly since bypassing execution policy is not required merely to run `Get-Process`). **Confidence: High** that this represents reconnaissance activity; **Not Established** that any data was exfiltrated or that persistence was created, since no such evidence appears in the logs.

---

## 7. Linux Command Analysis

| Command | Purpose | Investigative Relevance |
|---|---|---|
| `id` | Show current user/group identity | Common first check after privilege escalation to confirm effective permissions. |
| `cat /etc/passwd` | List all local accounts on the system | Account discovery — used by attackers to identify other accounts to target; also used legitimately by admins auditing accounts. |
| `ip addr` | Display network interfaces/addresses | Network discovery — mirrors the Windows `ipconfig /all` action. |
| `ss -tulpn` | List listening TCP/UDP sockets with owning processes | Discovery of running services/open ports — mirrors the Windows `netstat -ano` action. |

**Assessment:** As with the Windows commands, none of these are individually malicious — they are standard Linux administrative/troubleshooting commands. Their significance here comes from being executed, via `sudo` as root, immediately after a brute-force-then-success SSH login, and from directly mirroring the discovery sequence performed on WIN-SRV01 (identity → accounts → network → services/ports). **Confidence: High** that this represents reconnaissance; the parallel structure with the Windows activity strengthens the correlation between the two platforms.

---

## 8. Cross-Platform Correlation

| Correlation Factor | Linux Evidence | Windows Evidence | Assessment |
|---|---|---|---|
| Username | `sanket` (auth.log, syslog) | `sanket` (Security log, PowerShell log) | Same account used on both platforms |
| Source IP | `185.220.101.44` (SSH failures/success) | `185.220.101.44` (RDP failures/success) | Identical external IP used against both platforms |
| Timing | Brute-force success at 09:02:06 | Brute-force success at 09:03:29 | ~83 seconds apart — consistent with a single actor moving from one target to the next |
| Post-auth behavior | Identity → account list → network → ports (via `sudo`) | Identity → process list → account list → network → ports (via cmd/PowerShell) | Near-identical discovery pattern executed on both hosts |

**Correlation confidence:** **High.** The combination of identical username, identical source IP, closely-spaced timing, and a mirrored discovery-command sequence across two independent logging systems is strong, multi-source corroborating evidence that a single actor compromised or misused the `sanket` credentials to access both linux-srv01 and WIN-SRV01 in short succession. The subsequent WIN-SRV02 logon at 09:15:19 is correlated by username and timing (**Medium** confidence) but cannot be conclusively tied to the same source IP, since `10.10.20.15` is not confirmed in the logs as belonging to WIN-SRV01 or to the original attacker infrastructure.

---

## 9. Indicators of Compromise

| IOC | Type | Evidence Source | Timestamp | Confidence |
|---|---|---|---|---|
| `185.220.101.44` | Source IP | Linux auth.log (sshd); Windows Security Event Log (4625/4624) | 09:01:42 – 09:03:29 | High |
| `sanket` | Username | Windows Security Event Log; Linux auth.log/syslog | 08:42:11 – 09:15:19 | High |
| `WIN-SRV01` | Hostname | Windows Security Event Log | 08:42:11 – 09:12:45 | High |
| `WIN-SRV02` | Hostname | Windows Security Event Log | 09:15:19 | Medium |
| `linux-srv01` | Hostname | Linux auth.log/syslog | 09:01:42 – 09:12:38 | High |
| `net user`, `ipconfig /all`, `netstat -ano`, `whoami` | Command | Windows Security Event Log (4688) | 09:05:14 – 09:12:45 | High |
| `Get-Process`, `Get-Service`, `Get-LocalUser` | Command | PowerShell log (4104) | 09:05:31 – 09:06:32 | High |
| `id`, `cat /etc/passwd`, `ip addr`, `ss -tulpn` | Command | Linux auth.log (sudo) | 09:02:25 – 09:04:17 | High |
| `10.10.20.15` | Source IP (internal, WIN-SRV02 logon) | Windows Security Event Log (4624) | 09:15:19 | Medium |
| Port `51221` | Source port (SSH session) | Linux auth.log | 09:01:42 – 09:02:06 | Low (contextual only) |

No file hashes, malware names, domains, or persistence artifacts (e.g., new accounts, scheduled tasks, services) are present in the supplied logs.

---

## 10. MITRE ATT&CK Mapping

| Observed Activity | MITRE ATT&CK Technique | Technique ID | Evidence | Confidence |
|---|---|---|---|---|
| Repeated failed logins followed by success (SSH and RDP) from the same IP/account | Brute Force | T1110 | Multiple `4625`/failed-password entries followed by success on both platforms | High |
| Use of the `sanket` account to access multiple systems | Valid Accounts | T1078 | Successful logons on linux-srv01, WIN-SRV01, and WIN-SRV02 under `sanket` | High |
| RDP-based remote access | Remote Services: Remote Desktop Protocol | T1021.001 | `LogonType=10`, `AuthenticationPackage=Negotiate`, source `185.220.101.44` | High |
| SSH-based remote access | Remote Services: SSH | T1021.004 | `Accepted password for sanket ... ssh2` | High |
| `net user`, `Get-LocalUser`, `cat /etc/passwd` | Account Discovery | T1087 | Respective 4688/4104/sudo log entries | High |
| `ipconfig /all`, `ip addr` | System Network Configuration Discovery | T1016 | Respective 4688/sudo log entries | High |
| `netstat -ano`, `ss -tulpn` | System Network Connections Discovery | T1049 | Respective 4688/sudo log entries | High |
| `Get-Process`, `Get-Service`, `whoami`, `id` | System Owner/User & Process Discovery | T1033 / T1057 | Respective 4688/4104/sudo log entries | High |
| PowerShell used with `-ExecutionPolicy Bypass` for discovery | Command and Scripting Interpreter: PowerShell | T1059.001 | `powershell.exe -ExecutionPolicy Bypass -Command "Get-Process"` | High |
| `cmd.exe` used to chain discovery commands | Command and Scripting Interpreter: Windows Command Shell | T1059.003 | Multiple 4688 entries with `NewProcessName=cmd.exe` | High |
| `SeDebugPrivilege` assigned after logon | Access Token Manipulation / Abuse Elevation Control Mechanism (possible precursor) | T1134 / T1548 (inferred only) | `4672` event, `PrivilegeList=SeDebugPrivilege` | Low — assignment alone does not confirm technique use |
| Logon to a second host (WIN-SRV02) shortly after discovery activity on WIN-SRV01 | Lateral Movement (general) | TA0008 (tactic-level, technique not established) | `4624` on WIN-SRV02, `LogonType=3`, timing correlation | Medium |

---

## 11. L1 SOC Response Plan

### Immediate Actions

1. Validate the suspicious authentication events against SIEM/EDR for `sanket` on both WIN-SRV01 and linux-srv01.
2. Confirm whether `sanket` is a real, currently-employed user and whether they were expected to be accessing these systems at this time.
3. Contact the account owner (via an out-of-band channel, not email if account compromise is suspected) to confirm or deny the activity.
4. Search the SIEM for all activity associated with source IP `185.220.101.44` across the environment (not limited to these two hosts).
5. Search the SIEM for all activity associated with the `sanket` account across all systems, including WIN-SRV02.
6. Review endpoint telemetry (EDR) on WIN-SRV01, linux-srv01, and WIN-SRV02 for any additional process, file, or network activity beyond what appears in these logs.
7. Determine whether `10.10.20.15` corresponds to WIN-SRV01 or another internal system, to confirm or refute the lateral-movement hypothesis.
8. Escalate to L2/Incident Response — the correlated cross-platform brute-force-then-success pattern, combined with systematic discovery activity, meets the threshold for escalation.

### Containment Recommendations

- **Disable/lock the `sanket` account** through the organization's approved process, pending confirmation with the account owner — appropriate given the high-confidence brute-force-then-success pattern.
- **Reset the `sanket` account credentials** once the account owner is confirmed and account access is restored through an approved workflow.
- **Revoke active sessions/tokens** for `sanket` on WIN-SRV01, WIN-SRV02, and linux-srv01.
- **Block source IP `185.220.101.44`** at the perimeter firewall pending further investigation, given its direct role in the brute-force activity on two platforms.
- **Isolate WIN-SRV01 and linux-srv01** for forensic review if EDR/SIEM confirms activity beyond what is captured in these logs; isolation of WIN-SRV02 should be considered pending confirmation of the lateral-movement hypothesis.
- Do **not** take disruptive action against the `admin` account or `10.10.20.5`/`10.10.20.15` based solely on the current evidence — their activity does not meet the threshold for containment on its own.

---

## 12. Detection Rules the SOC Should Consider

| Detection | Log Source | Logic | Severity | Reason |
|---|---|---|---|---|
| Failed Login Followed by Success (Cross-Platform) | Windows Security (4625/4624) + Linux auth.log | Same username, same source IP, ≥2 failures followed by a success within a short window, correlated across both Windows and Linux logs within minutes of each other | High | Directly matches the confirmed pattern observed for `sanket`; cross-platform correlation is a strong compromise indicator |
| Suspicious Remote Login from External/Unrecognized IP | Windows Security (4624, LogonType 10) / Linux auth.log (sshd Accepted) | Successful remote logon from a source IP with no prior successful-logon history for that account | Medium-High | External-facing RDP/SSH access is a common initial-access vector; absence of baseline data lowers certainty slightly |
| Privileged Activity Shortly After Remote Login | Windows Security (4672) correlated with 4624 (LogonType 10); Linux `sudo` shortly after `sshd Accepted` | Privilege assignment or `sudo` usage within minutes of a remote interactive logon | Medium | Matches the `SeDebugPrivilege` assignment and rapid `sudo` usage observed for `sanket` |
| Suspicious PowerShell Activity After Remote Login | PowerShell log (4104) correlated with 4624 (LogonType 10) | PowerShell scriptblock execution, especially with `-ExecutionPolicy Bypass`, within minutes of a remote logon | Medium | Matches the `Get-Process`/`Get-Service`/`Get-LocalUser` activity with `-ExecutionPolicy Bypass` observed here |
| Cross-Host Account Activity | Windows Security (4624 across multiple hosts) | Same username authenticating to a second host within a short window following suspicious activity on a first host | Medium | Matches the `sanket` logon to WIN-SRV02 shortly after WIN-SRV01 discovery activity; confidence is medium pending IP attribution |

---

## 13. Final Investigation Report

### Incident Summary
Correlated Windows and Linux logs show the `sanket` account being accessed via brute-force-then-successful authentication from external IP `185.220.101.44` on both SSH (linux-srv01) and RDP (WIN-SRV01) within roughly 90 seconds of each other, followed immediately by matching discovery-command sequences on both hosts and a subsequent logon to a second Windows host (WIN-SRV02).

### Key Evidence
- 3 failed + 1 successful SSH login for `sanket` from `185.220.101.44` (09:01:42–09:02:06)
- 2 failed + 1 successful RDP login for `sanket` from `185.220.101.44` (09:03:17–09:03:29)
- Mirrored discovery command sequences on both platforms (identity → accounts → network → ports/services)
- `SeDebugPrivilege` assigned to `sanket` post-logon
- Subsequent `sanket` logon to WIN-SRV02 from `10.10.20.15`

### Affected Account
`sanket`

### Affected Hosts
WIN-SRV01 (primary), linux-srv01 (primary), WIN-SRV02 (secondary/possible lateral movement)

### Suspicious Source IP
`185.220.101.44`

### Primary Log Source
Correlated evidence across **Windows Security Event Log** and **Linux auth.log**; the cross-platform correlation itself is the strongest evidence, with Windows Security providing the clearest privilege/process detail and Linux auth.log providing the clearest brute-force pattern.

### Attack/Activity Timeline
See Section 3 (Chronological Investigation Timeline) — brute force (09:01–09:03) → successful authentication on two platforms → privilege assignment/sudo use (09:02–09:04) → discovery command execution (09:05–09:12) → secondary host logon (09:15).

### Evidence Confidence
**High** for the brute-force/authentication pattern and discovery command execution; **Medium** for privilege-escalation significance and the WIN-SRV02 lateral-movement hypothesis; **Not Established** for persistence, data theft, or malware, as no such evidence appears in the supplied logs.

### Indicators of Compromise
`185.220.101.44` (source IP), `sanket` (username), `WIN-SRV01`, `linux-srv01`, `WIN-SRV02` (hosts), and the discovery commands listed in Section 9.

### MITRE ATT&CK Mapping
See Section 10 — primarily Brute Force (T1110), Valid Accounts (T1078), Remote Services (T1021.001/T1021.004), and multiple Discovery techniques (T1087, T1016, T1049, T1033/T1057), plus Command and Scripting Interpreter (T1059.001/T1059.003).

### L1 Analyst Assessment
The correlated, multi-source evidence (identical username and source IP, closely-timed brute-force-then-success on two independent platforms, and mirrored discovery activity) meets the bar for a confirmed-compromise assessment at the L1 level. Persistence and data exfiltration are **not** established from the supplied logs and should not be assumed.

### Recommended Next Steps

| Priority | Next Step | Reason | Responsible Team | Evidence Supporting Action |
|---|---|---|---|---|
| High | Escalate to L2/Incident Response and lock/disable the `sanket` account pending confirmation with the account owner | Strong, correlated cross-platform brute-force-then-success pattern | L1 SOC → L2/IR | Findings #1–#5 (Section 2) |
| High | Block source IP `185.220.101.44` at the perimeter and search for related activity org-wide | Confirmed common source of the brute-force activity on two platforms | L1 SOC / Network Security | Findings #1–#2 (Section 2) |
| Medium | Confirm the identity/ownership of `10.10.20.15` and validate whether the WIN-SRV02 logon constitutes lateral movement | Cannot yet confirm the source of the WIN-SRV02 access | L1 SOC / IT Infrastructure | Finding #6 (Section 2) |
| Medium | Pull EDR telemetry from WIN-SRV01, WIN-SRV02, and linux-srv01 for activity beyond what is captured in these logs | Determine whether persistence, exfiltration, or additional tooling exists | L1 SOC / L2 IR | Section 6–7 command analysis |
| Low | Review `admin` account activity for completeness, though no anomaly is currently indicated | Rule out any coincidental relationship to the incident window | L1 SOC | Finding #7 (Section 2) |

### Escalation Recommendation
**Yes.**

### Analyst Assessment

**Finding:** Confirmed Compromise
**Evidence Confidence:** High
**Recommended Escalation:** Yes
**Primary Log Source:** Windows Security Event Log (RDP/process activity) and Linux auth.log (SSH brute-force pattern) — correlated
