# SOC Level 1 Manual Log Investigation

## Overview

This project demonstrates a manual Security Operations Center (SOC) Level 1 log investigation using Windows and Linux security logs.

The investigation focuses on identifying suspicious authentication activity, privileged activity, command execution, and activity across multiple systems.

## Objectives

- Analyze Windows Security logs
- Analyze Linux authentication logs
- Identify failed and successful authentication attempts
- Investigate privileged activity
- Identify suspicious command execution
- Build a chronological attack timeline
- Correlate events across systems
- Identify indicators of compromise (IOCs)
- Document investigation findings

## Systems Investigated

- WIN-SRV01
- WIN-SRV02
- linux-srv01

## Log Sources

### Windows

- Event ID 4624 – Successful Logon
- Event ID 4625 – Failed Logon
- Event ID 4672 – Special Privileges Assigned
- Event ID 4688 – Process Creation
- Event ID 4104 – PowerShell Script Block Logging

### Linux

- auth.log
- syslog
- SSH authentication events
- sudo activity

## Investigation

The investigation correlated authentication events, privileged activity, process execution, PowerShell activity, SSH activity, and sudo commands.

The detailed findings and evidence-confidence assessment are available in the investigation report.

## Repository Structure

```text
manual-log-investigation-soc/
│
├── README.md
│
├── report/
│   └── SOC_L1_Manual_Log_Investigation_Report.md
│
└── evidence/
    └── raw-logs.txt
