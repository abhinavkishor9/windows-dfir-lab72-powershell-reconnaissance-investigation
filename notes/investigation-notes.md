# Investigation Notes – PowerShell Reconnaissance Investigation

## Investigation Overview

This investigation examined PowerShell activity used to collect information about a Windows endpoint.

The investigation focused on system information, users, groups, administrator privileges, processes, services, network configuration, TCP connections, firewall configuration, and Microsoft Defender status.

The investigation also reviewed Windows and Sysmon telemetry to determine how much evidence was available to support the observed PowerShell activity.

The primary investigative question was:

**What information was PowerShell attempting to discover, who executed the commands, and does the observed sequence support normal administration or suspicious reconnaissance?**

The investigation followed an evidence-first approach. Reconnaissance was treated as an investigative signal rather than automatic proof of compromise.

## Host Information

| Attribute | Value |
|---|---|
| Hostname | `DESKTOP-GVRECLF` |
| Operating System | Windows 10 Home |
| OS Version | `10.0.19045` |
| User | `desktop-gvreclf\abhin` |
| IPv4 Address | `192.168.203.128` |
| Default Gateway | `192.168.203.2` |
| DNS Server | `192.168.203.2` |
| Lab Directory | `C:\PowerShellReconLab` |

## Investigation Objectives

The investigation was designed to:

- Identify the host and user context.
- Determine what system information was collected.
- Identify local users and groups.
- Determine administrator membership.
- Review running processes and services.
- Examine network configuration and active TCP connections.
- Identify the security controls present on the endpoint.
- Review PowerShell Script Block Logging.
- Correlate PowerShell process creation with Sysmon.
- Check Windows Security Event ID 4688.
- Validate file-creation telemetry using a controlled marker.
- Review network connection telemetry.
- Build a timeline of the available evidence.
- Determine whether malicious activity was established.

## 1. Lab Directory Creation

The investigation directory was created at:

`C:\PowerShellReconLab`

The directory was successfully created and verified.

This directory served as the controlled location for the investigation marker and provided a known path for subsequent telemetry validation.

## 2. System Discovery

The following commands were used to collect basic host information:

`hostname`

`$env:USERNAME`

`whoami`

`Get-ComputerInfo`

`Get-CimInstance Win32_OperatingSystem`

### Results

The host was identified as:

`DESKTOP-GVRECLF`

The active user was:

`desktop-gvreclf\abhin`

The operating system was:

`Microsoft Windows 10 Home`

Version:

`10.0.19045`

### Assessment

The activity confirms collection of basic host and identity information.

This is a standard discovery technique and does not independently indicate malicious behavior.

## 3. Process Discovery

Running processes were collected using:

`Get-Process | Select-Object Id, ProcessName, Path`

PowerShell was present in the process listing:

| Field | Value |
|---|---|
| Process | `powershell` |
| PID | `6608` |
| Path | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |

The process list also contained normal Windows and application processes.

### Assessment

Process discovery could allow an attacker to identify security tools, applications, and interesting processes.

No suspicious process was established from the available output.

The available process listing did not provide sufficient evidence to identify a malicious process chain.

## 4. Service Discovery

Windows services were enumerated using:

`Get-Service | Select-Object Name, Status, StartType`

### Assessment

Service discovery can provide information about:

- Security software
- Remote-management services
- Application services
- Automatically starting services
- Potentially interesting Windows components

The investigation did not identify malicious service creation or modification.

## 5. User Discovery

Local accounts were enumerated using:

`Get-LocalUser | Select-Object Name, Enabled, LastLogon`

### Results

| Account | Enabled |
|---|---|
| `abhin` | True |
| `Administrator` | False |
| `DefaultAccount` | False |
| `Guest` | False |
| `WDAGUtilityAccount` | False |

### Assessment

The command successfully identified local accounts.

User enumeration is a common reconnaissance technique because attackers may use it to understand the available identities on a compromised endpoint.

No credential theft or account manipulation was identified.

## 6. Group Discovery

Local groups were enumerated using:

`Get-LocalGroup | Select-Object Name, Description`

The output included groups such as:

- Administrators
- Device Owners
- Distributed COM Users
- Event Log Readers
- Guests
- Hyper-V Administrators
- IIS_IUSRS
- Performance Log Users
- Performance Monitor Users
- Remote Management Users
- System Managed Accounts Group
- Users

### Administrator Membership

The Administrators group was examined using:

`Get-LocalGroupMember -Group "Administrators"`

The following members were observed:

- `DESKTOP-GVRECLF\abhin`
- `DESKTOP-GVRECLF\Administrator`

### Assessment

The `abhin` account was confirmed as a local administrator.

This is important investigative context because an attacker performing reconnaissance may specifically look for privileged accounts.

However, no privilege-escalation activity was identified.

## 7. Network Configuration Discovery

Network configuration was collected using:

`Get-NetIPConfiguration`

### Results

| Attribute | Value |
|---|---|
| Interface Alias | `Ethernet0` |
| Interface Index | `4` |
| IPv4 Address | `192.168.203.128` |
| Default Gateway | `192.168.203.2` |
| DNS Server | `192.168.203.2` |

### Assessment

The command successfully identified the host's network configuration.

This type of discovery can be useful to an attacker attempting to understand the endpoint's network placement.

No malicious network configuration change was identified.

## 8. TCP Connection Discovery

Active TCP connections were reviewed using:

`Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess`

Multiple listening sockets were observed.

Examples included:

| Local Address | Local Port | PID |
|---|---:|---:|
| `::` | `49670` | `828` |
| `::` | `49668` | `1188` |
| `::` | `49667` | `1140` |
| `::` | `49666` | `1152` |
| `::` | `49665` | Output truncated |

### Assessment

The results confirm that PowerShell was used to inspect active TCP connection information.

The observed listening sockets were not considered malicious because the available output did not establish their associated applications or purpose.

## 9. Neighbor Discovery

Neighbor information was collected using:

`Get-NetNeighbor | Select-Object IPAddress, LinkLayerAddress, State`

This command can provide visibility into nearby network peers known to the host.

### Assessment

Neighbor discovery is consistent with network reconnaissance but can also be used for legitimate troubleshooting and network administration.

No malicious network activity was established from this command alone.

## 10. Firewall Discovery

Firewall configuration was reviewed using:

`Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction`

### Results

| Profile | Enabled | Default Inbound | Default Outbound |
|---|---|---|---|
| Domain | True | NotConfigured | NotConfigured |
| Private | True | NotConfigured | NotConfigured |
| Public | True | NotConfigured | NotConfigured |

### Assessment

All three Windows Firewall profiles were enabled.

The command demonstrates security-control discovery.

No evidence was identified showing that PowerShell disabled or modified the firewall.

## 11. Microsoft Defender Discovery

Microsoft Defender status was collected using:

`Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, AMServiceEnabled`

### Results

| Setting | Status |
|---|---|
| Antivirus | Enabled |
| Real-Time Protection | Enabled |
| Antimalware Service | Enabled |

### Assessment

The activity confirms that PowerShell queried Microsoft Defender configuration.

An attacker may perform similar discovery to identify security controls before attempting defense evasion.

However, no defense-evasion action was established.

## 12. Controlled Marker Creation

A controlled marker was created using:

`"LAB72 - PowerShell reconnaissance investigation" | Set-Content "C:\PowerShellReconLab\recon-marker.txt"`

The resulting file was verified using `Get-Item`.

### Results

| Attribute | Value |
|---|---|
| File | `recon-marker.txt` |
| Size | 50 bytes |
| Creation Time | `11-09-2026 07:05:38` |
| Last Write Time | `11-09-2026 07:05:38` |

The file existed successfully on the filesystem.

This provided a known artifact for testing Sysmon Event ID 11 visibility.

## 13. PowerShell Script Block Logging

PowerShell Operational logging was queried for Event ID `4104`.

The search included reconnaissance-related command names such as:

- `Get-ComputerInfo`
- `Get-Process`
- `Get-Service`
- `Get-LocalUser`
- `Get-LocalGroup`
- Network discovery commands

### Results

A current investigation-period result was observed at:

`11-09-2026 06:56:14`

Additional historical results were observed at:

- `09-09-2026 07:18:49`
- `31-08-2026 07:34:54`
- `28-08-2026 08:02:18`
- `25-08-2026 06:57:44`
- `22-08-2026 07:00:33`
- `21-08-2026 06:52:44`

### Assessment

Event ID 4104 provides supporting evidence that reconnaissance-related PowerShell script activity was logged.

The historical results were separated from the current activity because they occurred on previous dates.

The query did not exactly match every command executed during the lab, so it should not be interpreted as a complete reconstruction of the entire PowerShell session.

## 14. Sysmon Event ID 1

Sysmon Event ID `1` was queried for:

`powershell.exe`

### Observed Events

| Time | Event |
|---|---|
| `11-09-2026 06:44:48` | PowerShell process creation |
| `11-09-2026 06:45:10` | PowerShell process creation |
| `11-09-2026 06:46:16` | PowerShell process creation |
| `11-09-2026 06:46:19` | PowerShell process creation |
| `11-09-2026 06:48:00` | PowerShell process creation |
| `11-09-2026 06:48:37` | PowerShell process creation |

Additional historical PowerShell process-creation events were also present.

### Assessment

Sysmon confirms that PowerShell processes were created during the investigation period.

However, the available output did not expose complete command-line or parent-process information.

Therefore, the evidence confirms execution but does not establish whether the PowerShell processes originated from a suspicious parent process.

## 15. Security Event ID 4688

Windows Security Event ID `4688` was queried for PowerShell process creation.

### Result

No matching output was returned.

### Assessment

The absence of Event ID 4688 was treated as a telemetry limitation.

Sysmon Event ID 1 independently confirmed PowerShell process creation.

Potential reasons for the missing Security event include:

- Audit policy configuration
- Event filtering
- Event retention
- Differences between configured telemetry sources

The absence of one event source should not override evidence from another source.

## 16. Sysmon Event ID 11

Sysmon Event ID `11` was searched for the investigation marker:

`C:\PowerShellReconLab\recon-marker.txt`

### Result

No matching Event ID 11 output was returned.

### Assessment

The file was independently confirmed on the filesystem, so file creation is established.

The absence of Sysmon Event ID 11 means that the expected file-creation telemetry was not available in the queried results.

This is documented as a telemetry gap.

It should not be interpreted as evidence that the file was never created.

## 17. Sysmon Event ID 3

Sysmon Event ID `3` was reviewed for network activity.

Multiple connection events were observed between approximately:

`06:45` and `07:17`

### Assessment

The host generated network connection telemetry during the investigation period.

However, the available event output did not provide sufficient process-level information to establish that these connections originated from PowerShell.

Therefore:

**Network activity was confirmed, but PowerShell attribution was not confirmed.**

A stronger correlation would require matching:

- Timestamp
- Process ID
- Process image
- Source address
- Source port
- Destination address
- Destination port

within the same investigation window.

## 18. Reconnaissance Pattern

The overall activity can be represented as:

**PowerShell Execution**

↓

**System Discovery**

↓

**User and Group Discovery**

↓

**Process and Service Discovery**

↓

**Network Discovery**

↓

**Security Configuration Discovery**

This sequence is consistent with Windows reconnaissance.

However, reconnaissance activity can occur during both legitimate and malicious operations.

The sequence therefore represents a detection and investigation signal rather than proof of compromise.

## 19. Timeline

| Time | Evidence | Interpretation |
|---|---|---|
| `06:44:48` | Sysmon Event ID 1 | PowerShell process creation |
| `06:45:10` | Sysmon Event ID 1 | PowerShell process creation |
| `06:46:16` | Sysmon Event ID 1 | PowerShell process creation |
| `06:46:19` | Sysmon Event ID 1 | PowerShell process creation |
| `06:48:00` | Sysmon Event ID 1 | PowerShell process creation |
| `06:48:37` | Sysmon Event ID 1 | PowerShell process creation |
| `06:56:14` | PowerShell Event ID 4104 | Reconnaissance-related script block telemetry |
| `07:05:38` | Filesystem evidence | Investigation marker created |
| `07:05–07:17` | Sysmon Event ID 3 | Network connections observed |

The timeline demonstrates that PowerShell execution and reconnaissance-related telemetry were present during the investigation period.

The available evidence does not establish a malicious process chain or direct PowerShell ownership of the observed network connections.

## 20. Evidence Assessment

### Confirmed

- PowerShell execution occurred.
- Host information was collected.
- User information was collected.
- Local users and groups were enumerated.
- The `abhin` account was confirmed as a local administrator.
- Processes were enumerated.
- Services were enumerated.
- Network configuration was collected.
- TCP connections were reviewed.
- Neighbor information was queried.
- Firewall configuration was inspected.
- Microsoft Defender status was inspected.
- Reconnaissance-related PowerShell Event ID 4104 telemetry was observed.
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
- Direct PowerShell attribution for Sysmon Event ID 3 connections.
- Sysmon Event ID 11 telemetry for the marker file.
- Security Event ID 4688 telemetry for PowerShell.
- A suspicious PowerShell parent-child process relationship.

## 21. Telemetry Limitations

The investigation contained several telemetry limitations.

### Event ID 4688

No matching PowerShell process-creation event was returned from the Security log.

### Event ID 11

The marker file was created successfully, but no corresponding Sysmon file-creation event was returned.

### Event ID 3

Network connections were observed, but the available output did not provide sufficient process-level information for direct PowerShell attribution.

### Event ID 4104

The query returned both current and historical results, requiring careful separation of the investigation window.

### Event ID 1

PowerShell process creation was confirmed, but the available output did not expose complete parent-process and command-line context.

These limitations reduce confidence in process lineage and network attribution but do not invalidate the confirmed reconnaissance activity.

## 22. Investigative Conclusion

The investigation confirmed a sequence of PowerShell-based reconnaissance involving system, user, group, process, service, network, and security configuration discovery.

The activity is consistent with reconnaissance behavior, but the same commands can be used by administrators, security analysts, troubleshooters, and automated management tools.

No evidence was identified that conclusively demonstrated malicious execution, persistence, credential theft, command and control, or data exfiltration.

### Final Verdict

**Controlled PowerShell reconnaissance confirmed.**

**Malicious compromise not established.**

The activity should therefore be documented as confirmed discovery behavior with telemetry limitations rather than escalated solely because reconnaissance commands were executed.

## 23. Cleanup

The investigation directory was removed using:

`Remove-Item "C:\PowerShellReconLab" -Recurse -Force`

The cleanup was verified using:

`Test-Path "C:\PowerShellReconLab"`

Result:

`False`

The controlled lab artifacts were successfully removed.

## 24. DFIR Lessons

- PowerShell is a dual-use administrative technology.
- Discovery commands should be evaluated in context.
- Reconnaissance is a behavior, not automatic proof of compromise.
- User and privilege context can significantly improve investigation quality.
- Event ID 4104 can reveal useful PowerShell script activity.
- Sysmon Event ID 1 can confirm PowerShell process creation.
- Missing telemetry should be documented rather than ignored.
- Network events should be correlated with process information before attribution.
- Historical events must be separated from the active investigation timeline.
- Artifact existence and telemetry availability are separate questions.
- Follow-on execution, persistence, credential access, C2, and exfiltration should be investigated before declaring malicious compromise.
- The strongest SOC investigations **follow the evidence, not the assumption**.
