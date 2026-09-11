# Windows DFIR Lab 72 – PowerShell Reconnaissance Investigation

## Overview

This lab investigates PowerShell-based reconnaissance from a Windows DFIR and SOC perspective.

PowerShell is a legitimate Windows administration and automation tool, but it can also be used by attackers to collect information about a compromised system. Discovery activity may reveal operating-system details, users, administrator privileges, running processes, services, network configuration, active connections, and security controls.

In this controlled lab, PowerShell was used to perform system, user, group, process, service, network, firewall, and Microsoft Defender discovery on a Windows endpoint. A harmless marker file was also created to validate available file-system telemetry.

The investigation examined PowerShell Script Block Logging, Sysmon process creation, Windows Security Event ID 4688, Sysmon file creation, and Sysmon network connection telemetry.

The goal was to determine whether the observed activity represented controlled reconnaissance or evidence of malicious behavior, while avoiding the assumption that reconnaissance automatically indicates compromise.

## Environment

- Operating System: Windows 10 Home
- OS Version: `10.0.19045`
- Hostname: `DESKTOP-GVRECLF`
- User: `desktop-gvreclf\abhin`
- IPv4 Address: `192.168.203.128`
- Default Gateway: `192.168.203.2`
- DNS Server: `192.168.203.2`
- Host shell: Windows PowerShell
- Lab directory: `C:\PowerShellReconLab`

## Investigation Objectives

The investigation focused on:

- Collecting basic host and operating-system information.
- Identifying the current user and local accounts.
- Reviewing local groups and administrator membership.
- Enumerating running processes and Windows services.
- Collecting network configuration and TCP connection information.
- Reviewing Windows Firewall configuration.
- Checking Microsoft Defender status.
- Investigating PowerShell Script Block Logging using Event ID 4104.
- Investigating PowerShell process creation using Sysmon Event ID 1.
- Checking Windows Security Event ID 4688.
- Investigating the controlled marker file using Sysmon Event ID 11.
- Reviewing Sysmon Event ID 3 network telemetry.
- Building a timeline from the available evidence.
- Assessing reconnaissance activity without assuming malicious intent.

## Lab Directory Setup

The investigation directory was created at:

`C:\PowerShellReconLab`

The directory was successfully created and used as the controlled working location for the lab.

The directory was later used to create a harmless investigation marker for validating file-creation telemetry.

## Host and User Discovery

Basic host and identity information was collected using PowerShell commands including:

`hostname`

`$env:USERNAME`

`whoami`

`Get-ComputerInfo`

`Get-CimInstance Win32_OperatingSystem`

The host was identified as `DESKTOP-GVRECLF` running Windows 10 Home, version `10.0.19045`.

The current user was:

`desktop-gvreclf\abhin`

This established the host and user context before reviewing the remaining reconnaissance activity.

## Process and Service Discovery

Running processes were enumerated using:

`Get-Process`

Windows services were enumerated using:

`Get-Service`

The process output included normal Windows applications and services, including PowerShell itself:

`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

Process and service discovery can be useful to both administrators and attackers. The available process output did not establish a suspicious process or malicious service.

## User and Group Discovery

Local accounts and groups were reviewed using:

`Get-LocalUser`

`Get-LocalGroup`

`Get-LocalGroupMember -Group "Administrators"`

The local `abhin` account was enabled and was a member of the local Administrators group.

The Administrators group contained:

- `DESKTOP-GVRECLF\abhin`
- `DESKTOP-GVRECLF\Administrator`

Administrator membership is relevant during reconnaissance because attackers may identify privileged accounts before attempting further actions.

However, administrator membership alone does not establish privilege escalation.

## Network Discovery

Network configuration was collected using:

`Get-NetIPConfiguration`

The host was configured with:

| Attribute | Value |
|---|---|
| Interface | `Ethernet0` |
| IPv4 Address | `192.168.203.128` |
| Default Gateway | `192.168.203.2` |
| DNS Server | `192.168.203.2` |

Active TCP connections were reviewed using:

`Get-NetTCPConnection`

Multiple listening sockets were observed.

Network discovery provides useful information about the host and its communication environment, but the observed listening sockets were not considered suspicious based solely on the available output.

## Security Configuration Discovery

Windows Firewall configuration was reviewed using:

`Get-NetFirewallProfile`

The Domain, Private, and Public profiles were enabled.

Microsoft Defender status was checked using:

`Get-MpComputerStatus`

The results showed:

- Antivirus enabled.
- Real-time protection enabled.
- Antimalware service enabled.

This confirms that PowerShell was used to inspect security controls on the endpoint.

No evidence of firewall modification or Defender disabling was established.

## Investigation Marker

A controlled marker file was created at:

`C:\PowerShellReconLab\recon-marker.txt`

The file contained:

`LAB72 - PowerShell reconnaissance investigation`

The marker was successfully created and verified.

Observed metadata:

| Attribute | Value |
|---|---|
| File | `recon-marker.txt` |
| Size | 50 bytes |
| Creation Time | `11-09-2026 07:05:38` |
| Last Write Time | `11-09-2026 07:05:38` |

The marker was created specifically to determine whether the expected file-creation event was available in Sysmon telemetry.

## PowerShell Event ID 4104

PowerShell Script Block Logging was investigated using Event ID `4104`.

Reconnaissance-related PowerShell activity was identified in the available results.

A current investigation-period result was observed at:

`11-09-2026 06:56:14`

Additional historical Event ID 4104 results were also returned from previous dates.

The historical events were treated separately from the current investigation because they did not belong to the same activity window.

Event ID 4104 provides useful visibility into PowerShell script content and can help an analyst determine what commands were executed rather than relying only on process creation.

## Sysmon Event ID 1

Sysmon Event ID `1` was queried for `powershell.exe`.

Multiple PowerShell process-creation events were observed on `11-09-2026`, including:

| Time | Event |
|---|---|
| `06:44:48` | PowerShell process creation |
| `06:45:10` | PowerShell process creation |
| `06:46:16` | PowerShell process creation |
| `06:46:19` | PowerShell process creation |
| `06:48:00` | PowerShell process creation |
| `06:48:37` | PowerShell process creation |

These events confirm PowerShell execution.

The available output did not provide complete parent-process and command-line information, so a suspicious process relationship could not be established.

## Security Event ID 4688

Windows Security Event ID `4688` was queried for `powershell.exe`.

No matching output was returned.

This was treated as a telemetry limitation rather than evidence that PowerShell was not executed.

Sysmon Event ID 1 independently confirmed PowerShell process creation.

Possible explanations include audit-policy configuration, event filtering, retention, or differences between telemetry sources.

## Sysmon Event ID 11

Sysmon Event ID `11` was queried for:

`C:\PowerShellReconLab\recon-marker.txt`

No matching Event ID 11 result was returned.

However, the file was successfully created and verified on the filesystem.

This demonstrates that the absence of a specific telemetry event does not necessarily mean the underlying action did not occur.

The missing Event ID 11 result was therefore documented as a telemetry gap.

## Sysmon Event ID 3

Sysmon Event ID `3` network telemetry showed multiple network connection events during the investigation period.

Events were observed between approximately `06:45` and `07:17` on `11-09-2026`.

However, the available output did not provide sufficient process-level information to establish that these connections originated from PowerShell.

Therefore:

**Network activity was observed, but direct attribution to PowerShell was not established.**

Process ID, timestamp, image, source address, destination address, and port information would be required for stronger correlation.

## Evidence Assessment

### Confirmed

- PowerShell execution occurred.
- System information was collected.
- User and group information was collected.
- Administrator membership was identified.
- Processes and services were enumerated.
- Network configuration was collected.
- TCP connection information was reviewed.
- Firewall configuration was inspected.
- Microsoft Defender status was inspected.
- PowerShell Event ID 4104 contained reconnaissance-related activity.
- Sysmon Event ID 1 recorded PowerShell process creation.
- The controlled marker file was successfully created.

### Not Established

- Malicious intent.
- Unauthorized access.
- Credential theft.
- Privilege escalation.
- Persistence.
- Defense evasion.
- Malicious payload execution.
- Command and control.
- Data exfiltration.
- Direct PowerShell attribution for the observed Sysmon Event ID 3 connections.
- Sysmon Event ID 11 telemetry for the marker file.
- Security Event ID 4688 telemetry for PowerShell.

## Investigative Conclusion

The investigation confirmed a PowerShell reconnaissance sequence involving host, user, group, process, service, network, and security configuration discovery.

The activity is consistent with Windows reconnaissance, but the same commands can also be used during legitimate administration, troubleshooting, security testing, and DFIR activities.

Based on the available evidence, **controlled PowerShell reconnaissance was confirmed, while malicious intent or system compromise was not established**.

## Cleanup

The investigation directory was removed using:

`Remove-Item "C:\PowerShellReconLab" -Recurse -Force`

The directory was then verified using:

`Test-Path "C:\PowerShellReconLab"`

The result was:

`False`

The controlled lab artifacts were successfully removed.

## DFIR Lessons

- PowerShell is a legitimate dual-use Windows tool.
- Discovery commands are not inherently malicious.
- Reconnaissance should be evaluated as a sequence rather than as isolated commands.
- User context and administrator membership provide important investigative context.
- PowerShell Event ID 4104 can provide visibility into executed script content.
- Sysmon Event ID 1 can confirm PowerShell process creation.
- Missing telemetry should be documented as a limitation.
- Network activity should not be attributed to PowerShell without process-level correlation.
- Historical telemetry should be separated from the current investigation timeline.
- Reconnaissance should be correlated with execution, persistence, credential access, C2, or exfiltration before declaring compromise.
- The investigation should always follow the evidence, not the assumption.
