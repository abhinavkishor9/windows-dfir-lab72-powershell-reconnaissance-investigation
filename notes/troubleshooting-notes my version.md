# Troubleshooting Notes 

## 1. Lab Directory Validation

### Issue

The investigation required a dedicated directory for the controlled lab activity.

### Check

The directory was created using:

`New-Item -Path "C:\PowerShellReconLab" -ItemType Directory -Force`

The directory was then verified with:

`Get-Item "C:\PowerShellReconLab"`

### Result

The directory was created successfully.

The creation time was observed as:

`11-09-2026 06:45`

### Resolution

No issue was identified.

The directory was available for the remainder of the investigation.

## 2. PowerShell Reconnaissance Commands

### Issue

The investigation required multiple discovery commands covering different areas of the Windows host.

### Checks Performed

System information:

`Get-ComputerInfo`

Operating-system information:

`Get-CimInstance Win32_OperatingSystem`

Process discovery:

`Get-Process`

Service discovery:

`Get-Service`

User discovery:

`Get-LocalUser`

Group discovery:

`Get-LocalGroup`

Administrator membership:

`Get-LocalGroupMember -Group "Administrators"`

Network configuration:

`Get-NetIPConfiguration`

TCP connections:

`Get-NetTCPConnection`

Neighbour information:

`Get-NetNeighbor`

Firewall configuration:

`Get-NetFirewallProfile`

Microsoft Defender status:

`Get-MpComputerStatus`

### Result

The commands executed successfully and returned the expected Windows host information.

### Resolution

No command-execution problem was identified.

The main troubleshooting requirement was interpreting the collected information correctly rather than assuming that discovery activity was malicious.

## 3. Confirming Administrator Context

### Issue

The investigation needed to establish the privilege level of the account executing the reconnaissance commands.

### Check

The local Administrators group was reviewed using:

`Get-LocalGroupMember -Group "Administrators"`

### Result

The output showed:

- `DESKTOP-GVRECLF\abhin`
- `DESKTOP-GVRECLF\Administrator`

The `abhin` account was therefore confirmed as a local administrator.

### Resolution

The user context was documented as part of the investigation.

Administrator membership was treated as investigative context and not as evidence of privilege escalation.

## 4. PowerShell Event ID 4104 Investigation

### Issue

PowerShell Script Block Logging needed to be validated to determine whether reconnaissance-related PowerShell activity was being recorded.

### Check

The PowerShell Operational log was queried for Event ID `4104`.

The investigation searched for reconnaissance-related command names.

### Result

A current investigation-period result was observed at:

`11-09-2026 06:56:14`

Additional results were also returned from previous dates.

### Troubleshooting Consideration

The query returned both current and historical events.

Therefore, not every returned event could be assumed to belong to the current investigation.

The search also did not exactly match every command used during the lab.

### Resolution

The results were separated into:

- Current investigation telemetry
- Historical telemetry
- Commands not directly represented by the search filter

Event ID 4104 was therefore treated as supporting evidence rather than a complete reconstruction of the PowerShell session.

## 5. Sysmon Event ID 1 Validation

### Issue

PowerShell process creation needed to be confirmed independently from the PowerShell log.

### Check

Sysmon Event ID `1` was queried for:

`powershell.exe`

### Result

Multiple PowerShell process-creation events were observed on `11-09-2026`.

Observed times included:

- `06:44:48`
- `06:45:10`
- `06:46:16`
- `06:46:19`
- `06:48:00`
- `06:48:37`

### Resolution

PowerShell process creation was confirmed.

However, the available output did not expose complete parent-process and command-line information.

The investigation therefore confirmed execution without making assumptions about the process origin.

## 6. Security Event ID 4688 Missing

### Issue

A search for PowerShell process creation using Windows Security Event ID `4688` returned no results.

### Check

The Security log was queried for:

`powershell.exe`

### Result

No matching event was returned.

### Troubleshooting Analysis

This result initially appears inconsistent with the Sysmon Event ID 1 results.

However, different Windows telemetry sources have different logging requirements and configurations.

Possible reasons include:

- Process creation auditing was not enabled.
- Events were filtered.
- Relevant events were not retained.
- The available Security log did not contain the expected records.

### Resolution

Sysmon Event ID 1 was used as the available source confirming PowerShell process creation.

The missing Security Event ID 4688 was documented as a telemetry limitation.

It was not interpreted as evidence that PowerShell was never executed.

## 7. Marker File Creation

### Issue

A controlled file was required to validate whether Sysmon file-creation telemetry was available.

### Action

The following marker was created:

`C:\PowerShellReconLab\recon-marker.txt`

The file contained:

`LAB72 - PowerShell reconnaissance investigation`

### Verification

The file was checked using:

`Get-Item "C:\PowerShellReconLab\recon-marker.txt"`

### Result

The file was successfully created.

Observed metadata:

| Attribute | Value |
|---|---|
| File | `recon-marker.txt` |
| Size | 50 bytes |
| Creation Time | `11-09-2026 07:05:38` |
| Last Write Time | `11-09-2026 07:05:38` |

### Resolution

The filesystem confirmed successful file creation.

## 8. Sysmon Event ID 11 Missing

### Issue

The marker file was created successfully, but a Sysmon Event ID `11` search for the marker returned no results.

### Check

The investigation searched for:

`PowerShellReconLab`

and:

`recon-marker.txt`

### Result

No matching Event ID 11 output was returned.

### Troubleshooting Analysis

The filesystem provided direct evidence that the file existed.

Therefore, the missing Sysmon event did not invalidate the file-creation evidence.

Possible explanations include:

- Sysmon configuration
- Event filtering
- Event collection limitations
- Event retention
- Query limitations

### Resolution

The file creation was recorded as confirmed from filesystem evidence.

The absence of Event ID 11 was documented as a telemetry gap.

## 9. Sysmon Event ID 3 Network Telemetry

### Issue

Network connections were visible in Sysmon, but it was necessary to determine whether they could be attributed to PowerShell.

### Check

Sysmon Event ID `3` was reviewed for network connection activity.

### Result

Multiple network connection events were observed between approximately:

`06:45` and `07:17`

### Troubleshooting Analysis

The available output showed network connection events but did not provide enough process-level information to establish that PowerShell generated them.

It would be incorrect to assume:

`Network Event = PowerShell Network Activity`

without correlating the process information.

### Resolution

The network activity was documented as:

**Network connections observed; PowerShell attribution not established.**

A stronger investigation would correlate:

- Timestamp
- Process ID
- Process image
- Source address
- Source port
- Destination address
- Destination port

## 10. TCP Listening Sockets

### Issue

The `Get-NetTCPConnection` output showed multiple listening sockets.

### Check

The following information was reviewed:

`LocalAddress`

`LocalPort`

`RemoteAddress`

`RemotePort`

`State`

`OwningProcess`

### Result

Examples included:

| Local Address | Local Port | PID |
|---|---:|---:|
| `::` | `49670` | `828` |
| `::` | `49668` | `1188` |
| `::` | `49667` | `1140` |
| `::` | `49666` | `1152` |
| `::` | `49665` | Output truncated |

### Troubleshooting Analysis

Listening ports are not automatically suspicious.

Windows commonly exposes multiple local services and RPC-related listeners.

The available evidence did not identify these sockets as malicious.

### Resolution

The listeners were documented without assigning a malicious classification.

Further investigation would require mapping each PID to its process and expected Windows service.

## 11. PowerShell Command Filtering Consideration

### Issue

The Event ID 4104 search used command-name matching.

Some command names in the search filter did not exactly match the commands used during the lab.

For example, the investigation used:

`Get-NetIPConfiguration`

and:

`Get-NetNeighbor`

while the search expression contained different command-name variants.

### Impact

A search query can return incomplete results when the search terms do not exactly match the executed commands.

Therefore, the absence of a command from the query results should not automatically be interpreted as evidence that the command was not executed.

### Resolution

The Event ID 4104 results were treated as supporting evidence rather than a complete command inventory.

For a production investigation, the analyst should review the full Event ID 4104 message content and use broader but controlled search terms.

## 12. Historical Telemetry

### Issue

The PowerShell and Sysmon searches returned events from previous dates.

Historical examples included PowerShell Event ID 4104 events from:

- `09-09-2026`
- `31-08-2026`
- `28-08-2026`
- `25-08-2026`
- `22-08-2026`
- `21-08-2026`

### Troubleshooting Analysis

Historical telemetry can create false correlations if it is automatically grouped with current activity.

For example, an old PowerShell event should not be treated as part of the current reconnaissance sequence without timestamp correlation.

### Resolution

Events were separated into:

- Current investigation period
- Historical activity

Only events relevant to the current timeline were used for direct correlation.

## 13. Process Attribution Limitation

### Issue

Sysmon Event ID 1 confirmed PowerShell process creation, but the available output did not show complete parent-child process information.

### Impact

Without the parent process and full command line, it was not possible to determine whether PowerShell was launched from:

- Explorer
- Command Prompt
- Another PowerShell process
- A scheduled task
- A script
- A potentially suspicious application

### Resolution

The investigation confirmed PowerShell execution but did not classify the process chain as suspicious.

For a production investigation, the analyst should review:

- `ProcessId`
- `ParentProcessId`
- `Image`
- `CommandLine`
- `ParentImage`
- `ParentCommandLine`
- `User`
- `IntegrityLevel`

## 14. Telemetry Correlation Issue

### Problem

Different telemetry sources provided different levels of visibility.

| Telemetry | Result |
|---|---|
| PowerShell Event ID 4104 | Reconnaissance-related activity observed |
| Sysmon Event ID 1 | PowerShell process creation confirmed |
| Security Event ID 4688 | No matching result |
| Sysmon Event ID 11 | No marker-file event returned |
| Sysmon Event ID 3 | Network activity observed |
| Filesystem | Marker file creation confirmed |

### Assessment

No single telemetry source provided the complete investigation story.

The strongest assessment therefore came from correlating the available evidence while explicitly documenting missing telemetry.

