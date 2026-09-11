# Timeline – PowerShell Reconnaissance Investigation

## Timeline Overview

This timeline reconstructs the available evidence from the PowerShell reconnaissance investigation.

The timeline focuses on PowerShell process creation, PowerShell Script Block Logging, the controlled marker-file creation, and Sysmon network activity.

Only events supported by the available telemetry are included. Where exact command execution or process attribution could not be established, the limitation is explicitly documented.

## Investigation Timeline

| Date | Time | Source | Event | Assessment |
|---|---|---|---|---|
| 11-09-2026 | 06:44:48 | Sysmon Event ID 1 | `powershell.exe` process creation | PowerShell execution confirmed |
| 11-09-2026 | 06:45:10 | Sysmon Event ID 1 | `powershell.exe` process creation | PowerShell execution confirmed |
| 11-09-2026 | 06:45:35 | Sysmon Event ID 3 | Network connection detected | Network activity observed; process attribution not established |
| 11-09-2026 | 06:45:36 | Sysmon Event ID 3 | Network connection detected | Network activity observed; process attribution not established |
| 11-09-2026 | 06:45:37 | Sysmon Event ID 3 | Network connection detected | Network activity observed; process attribution not established |
| 11-09-2026 | 06:45:45 | Sysmon Event ID 3 | Network connection detected | Network activity observed; process attribution not established |
| 11-09-2026 | 06:45:46 | Sysmon Event ID 3 | Network connection detected | Network activity observed; process attribution not established |
| 11-09-2026 | 06:46:16 | Sysmon Event ID 1 | `powershell.exe` process creation | PowerShell execution confirmed |
| 11-09-2026 | 06:46:19 | Sysmon Event ID 1 | `powershell.exe` process creation | PowerShell execution confirmed |
| 11-09-2026 | 06:46:23 | Sysmon Event ID 3 | Network connection detected | Network activity observed; process attribution not established |
| 11-09-2026 | 06:46:29 | Sysmon Event ID 3 | Network connection detected | Network activity observed; process attribution not established |
| 11-09-2026 | 06:47:19 | Sysmon Event ID 3 | Network connection detected | Network activity observed; process attribution not established |
| 11-09-2026 | 06:47:27 | Sysmon Event ID 3 | Network connection detected | Network activity observed; process attribution not established |
| 11-09-2026 | 06:47:59 | Sysmon Event ID 3 | Network connection detected | Network activity observed; process attribution not established |
| 11-09-2026 | 06:48:00 | Sysmon Event ID 1 | `powershell.exe` process creation | PowerShell execution confirmed |
| 11-09-2026 | 06:48:21 | Sysmon Event ID 3 | Network connection detected | Network activity observed; process attribution not established |
| 11-09-2026 | 06:48:37 | Sysmon Event ID 1 | `powershell.exe` process creation | PowerShell execution confirmed |
| 11-09-2026 | 06:50:20 | Sysmon Event ID 3 | Network connection detected | Network activity observed; process attribution not established |
| 11-09-2026 | 06:52:57 | Sysmon Event ID 3 | Network connection detected | Network activity observed; process attribution not established |
| 11-09-2026 | 06:53:45 | Sysmon Event ID 3 | Network connection detected | Network activity observed; process attribution not established |
| 11-09-2026 | 06:54:13 | Sysmon Event ID 3 | Network connection detected | Network activity observed; process attribution not established |
| 11-09-2026 | 06:55:15 | Sysmon Event ID 3 | Network connection detected | Network activity observed; process attribution not established |
| 11-09-2026 | 06:55:41 | Sysmon Event ID 3 | Network connection detected | Network activity observed; process attribution not established |
| 11-09-2026 | 06:56:14 | PowerShell Event ID 4104 | Reconnaissance-related script block telemetry | PowerShell discovery activity supported |
| 11-09-2026 | 06:59:26 | Sysmon Event ID 3 | Network connection detected | Network activity observed; process attribution not established |
| 11-09-2026 | 06:59:28 | Sysmon Event ID 3 | Network connection detected | Network activity observed; process attribution not established |
| 11-09-2026 | 07:00:57 | Sysmon Event ID 3 | Network connection detected | Network activity observed; process attribution not established |
| 11-09-2026 | 07:01:18 | Sysmon Event ID 3 | Network connection detected | Network activity observed; process attribution not established |
| 11-09-2026 | 07:02:19 | Sysmon Event ID 3 | Network connection detected | Network activity observed; process attribution not established |
| 11-09-2026 | 07:03:02 | Sysmon Event ID 3 | Network connection detected | Network activity observed; process attribution not established |
| 11-09-2026 | 07:04:46 | Sysmon Event ID 3 | Network connection detected | Network activity observed; process attribution not established |
| 11-09-2026 | 07:05:07 | Sysmon Event ID 3 | Network connection detected | Network activity observed; process attribution not established |
| 11-09-2026 | 07:05:38 | Filesystem | `recon-marker.txt` created | Controlled marker creation confirmed |
| 11-09-2026 | 07:05:41 | Sysmon Event ID 3 | Network connection detected | Network activity observed; process attribution not established |
| 11-09-2026 | 07:06:37 | Sysmon Event ID 3 | Network connection detected | Network activity observed; process attribution not established |
| 11-09-2026 | 07:07:17 | Sysmon Event ID 3 | Network connection detected | Network activity observed; process attribution not established |
| 11-09-2026 | 07:10:00 | Sysmon Event ID 3 | Network connection detected | Network activity observed; process attribution not established |
| 11-09-2026 | 07:10:05 | Sysmon Event ID 3 | Network connection detected | Network activity observed; process attribution not established |
| 11-09-2026 | 07:11:57 | Sysmon Event ID 3 | Network connection detected | Network activity observed; process attribution not established |
| 11-09-2026 | 07:12:18 | Sysmon Event ID 3 | Network connection detected | Network activity observed; process attribution not established |
| 11-09-2026 | 07:13:44 | Sysmon Event ID 3 | Network connection detected | Network activity observed; process attribution not established |
| 11-09-2026 | 07:14:06 | Sysmon Event ID 3 | Network connection detected | Network activity observed; process attribution not established |
| 11-09-2026 | 07:15:08 | Sysmon Event ID 3 | Network connection detected | Network activity observed; process attribution not established |
| 11-09-2026 | 07:15:34 | Sysmon Event ID 3 | Network connection detected | Network activity observed; process attribution not established |
| 11-09-2026 | 07:15:37 | Sysmon Event ID 3 | Network connection detected | Network activity observed; process attribution not established |
| 11-09-2026 | 07:16:15 | Sysmon Event ID 3 | Network connection detected | Network activity observed; process attribution not established |
| 11-09-2026 | 07:17:31 | Sysmon Event ID 3 | Network connection detected | Network activity observed; process attribution not established |

## Key Investigation Events

### 06:44:48–06:48:37 – PowerShell Execution

Multiple Sysmon Event ID 1 records confirmed the creation of `powershell.exe` processes during the investigation period.

The available output confirmed execution but did not provide complete parent-process or command-line information.

### 06:56:14 – PowerShell Script Block Logging

PowerShell Event ID 4104 returned reconnaissance-related script block telemetry.

This provided supporting evidence that PowerShell was being used for discovery activity.

Historical Event ID 4104 events were also present but were treated separately from the current investigation.

### 07:05:38 – Controlled Marker Creation

The investigation marker:

`C:\PowerShellReconLab\recon-marker.txt`

was created at:

`11-09-2026 07:05:38`

The file was successfully verified on the filesystem.

No corresponding Sysmon Event ID 11 result was returned.

### 07:05–07:17 – Network Activity

Multiple Sysmon Event ID 3 events were observed during this period.

The presence of network connection telemetry was confirmed, but the available evidence did not establish that the connections originated from PowerShell.

## Historical Telemetry

The investigation also returned PowerShell Event ID 4104 records from previous dates.

| Date | Time | Source |
|---|---|---|
| 09-09-2026 | 07:18:49 | PowerShell Event ID 4104 |
| 31-08-2026 | 07:34:54 | PowerShell Event ID 4104 |
| 28-08-2026 | 08:02:18 | PowerShell Event ID 4104 |
| 25-08-2026 | 06:57:44 | PowerShell Event ID 4104 |
| 22-08-2026 | 07:00:33 | PowerShell Event ID 4104 |
| 21-08-2026 | 06:52:44 | PowerShell Event ID 4104 |

These events were not automatically associated with the current investigation.

Historical telemetry must be separated from current activity unless timestamp, process, user, and other evidence establish a relationship.

## Telemetry Gaps

| Event Source | Result | Impact |
|---|---|---|
| PowerShell Event ID 4104 | Reconnaissance-related activity observed | Supports PowerShell discovery |
| Sysmon Event ID 1 | PowerShell process creation observed | Confirms execution |
| Security Event ID 4688 | No matching PowerShell result | Process creation could not be independently confirmed through Security logging |
| Sysmon Event ID 11 | No marker-file event returned | File creation confirmed through filesystem, but Sysmon telemetry unavailable |
| Sysmon Event ID 3 | Multiple network events observed | Network activity confirmed, PowerShell attribution not established |

## Timeline Interpretation

The available evidence supports the following sequence:

**PowerShell Execution**

↓

**System and User Discovery**

↓

**Process and Service Discovery**

↓

**Network Discovery**

↓

**Security Configuration Discovery**

↓

**Controlled Marker Creation**

↓

**Continued Network Telemetry**

This sequence is consistent with PowerShell reconnaissance.

However, the timeline does not establish malicious intent, compromise, command and control, or exfiltration.

## Final Timeline Assessment

The timeline confirms that PowerShell was executed and that reconnaissance-related PowerShell activity was logged during the investigation.

The controlled marker was successfully created at `07:05:38`, while Sysmon Event ID 11 did not provide a corresponding file-creation event.

Network connection events were observed throughout the investigation window, but the available telemetry was insufficient to attribute those connections directly to PowerShell.

### Final Verdict

**PowerShell reconnaissance activity confirmed.**

**Malicious compromise not established.**

The timeline therefore supports a controlled reconnaissance investigation with documented telemetry limitations rather than a confirmed malicious intrusion.
