# microsoft-defender-incident-investigation

## Overview
A security alert has been generated in Microsoft Defender XDR. As the SOC analyst, your task is to investigate the incident and determine what evidence is available, what activity can be established, and whether the incident can be confirmed as malicious.

The investigation should follow an evidence-first approach:

Incident
   ↓
Alert
   ↓
Affected Device / User
   ↓
Alert Evidence
   ↓
Device Timeline
   ↓
Process Tree
   ↓
Advanced Hunting
   ↓
Live Response
   ↓
Timeline Reconstruction
   ↓
Investigation Conclusion

Because your Defender environment has repeatedly shown limited or unavailable endpoint telemetry, the lab should explicitly allow for a telemetry-limited investigation. You should document missing evidence instead of creating artificial findings.


Microsoft Defender XDR provides security teams with centralized visibility into security incidents, alerts, endpoint activity, and investigation data.

In a typical SOC investigation, an analyst begins with an incident or alert and then examines associated entities, endpoint activity, process execution, file activity, network activity, and supporting telemetry.

This lab followed that investigation workflow using the Microsoft Defender portal.

The investigation focused on:

- Microsoft Defender Incidents
- Microsoft Defender Alerts
- Advanced Hunting
- Kusto Query Language (KQL)
- Process execution telemetry
- PowerShell activity
- Encoded PowerShell hunting
- File activity
- Endpoint telemetry availability
- Evidence limitations

The environment was also assessed for the availability of endpoint telemetry before drawing any security conclusions.

---

## Investigation Scenario

A SOC analyst is reviewing a Microsoft Defender XDR environment after a request to determine whether any suspicious endpoint activity can be identified. The analyst starts with the available Incidents and Alerts, then moves to Advanced Hunting to examine process, PowerShell, encoded PowerShell, and file activity.

During the investigation, the available Defender views and KQL queries return little or no endpoint data. The analyst must therefore determine whether this represents a clean environment or a telemetry visibility limitation, and document the conclusion based only on the evidence available.

Investigation focus:

- Review available security incidents and alerts.
- Hunt for relevant endpoint activity using KQL.
- Assess whether sufficient telemetry exists to support an investigation.
- Avoid treating empty results as proof that no activity occurred.

---

## Investigation Objectives

- Review Microsoft Defender XDR Incidents and Alerts.
- Navigate Advanced Hunting and its available schema.
- Use KQL to examine DeviceProcessEvents.
- Hunt for PowerShell execution.
- Hunt for encoded PowerShell activity.
- Review DeviceFileEvents for file activity.
- Assess endpoint telemetry availability.
- Distinguish absence of telemetry from absence of activity.
- Document investigation limitations and reach an evidence-based conclusion.

---

## Environment

| Component | Details |
|---|---|
| Platform | Microsoft Defender XDR |
| Investigation Area | Investigation & response |
| Hunting Capability | Advanced Hunting |
| Query Language | Kusto Query Language (KQL) |
| Process Table | `DeviceProcessEvents` |
| File Table | `DeviceFileEvents` |
| Investigation Window | Last 7 days |
| Incidents Available | 0 |
| Alerts Available | 0 |
| Process Events | 0 |
| File Events | 0 |

---

## Investigation Workflow

Microsoft Defender

↓

Incidents

↓

Alerts

↓

Advanced Hunting

↓

Review Schema

↓

Process Hunting

↓

PowerShell Hunting

↓

Encoded PowerShell Hunting

↓

File Activity

↓

Telemetry Assessment

↓

Investigation Conclusion

---

## Lab Activities

### 1. Review Incidents

The Microsoft Defender Incidents page was reviewed to determine whether any incidents were available.

The page provided investigation and filtering options including:

- Incident name
- Incident ID
- Priority
- Tags
- Severity
- Filter sets

### Observation

No incidents were available in the environment.

---

### 2. Review Alerts

The Alerts page was examined to determine whether individual security alerts were available.

The page provided:

- Alert search
- Alert filters
- Investigation state
- Status
- Severity

The environment displayed:

`0 Alerts`

---

### 3. Open Advanced Hunting

Advanced Hunting was opened from the Microsoft Defender investigation and response section.

The Advanced Hunting interface provided:

- KQL query editor
- Schema
- Run query
- Results
- Query history
- Filters

The investigation window was set to:

`Last 7 days`

---

### 4. Review Process Telemetry

The following KQL query was executed:

```kusto
DeviceProcessEvents
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName
| sort by Timestamp desc
```

Result:

`0 items`

No process-event records were returned.

---

### 5. Hunt for PowerShell

The following query was used:

```kusto
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

Result:

`0 items`

No PowerShell process telemetry was available.

---

### 6. Hunt for Encoded PowerShell

The following query was executed:

```kusto
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine contains "-EncodedCommand"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

Result:

`0 items`

No encoded PowerShell activity was returned.

Encoded PowerShell is a useful hunting indicator, but an empty result does not prove that encoded PowerShell was never executed.

---

### 7. Review File Activity

The following query was used:

```kusto
DeviceFileEvents
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName
| sort by Timestamp desc
```

Result:

`0 items`

No file-event telemetry was available.

---

## Key Findings

| Area | Finding |
|---|---|
| Incidents | 0 incidents |
| Alerts | 0 alerts |
| Process telemetry | 0 events |
| PowerShell telemetry | 0 events |
| Encoded PowerShell | 0 events |
| File telemetry | 0 events |
| Endpoint investigation | Limited |
| Final assessment | Insufficient endpoint telemetry |

---

## Important Investigation Note

An empty KQL result does not prove that the activity did not occur.

For example:

`0 PowerShell Events`

does not necessarily mean:

`PowerShell was never executed.`

It means:

`No PowerShell telemetry was returned by the queried data source.`

This distinction is important during SOC investigations.

---

## Investigation Outcome

The investigation confirmed that the Microsoft Defender investigation and Advanced Hunting interfaces were accessible.

However, the environment contained:

- No incidents
- No alerts
- No process telemetry
- No PowerShell telemetry
- No encoded PowerShell telemetry
- No file telemetry

Therefore, a complete endpoint-based incident investigation could not be performed.

The final assessment was:

**Insufficient endpoint telemetry to confirm or rule out suspicious endpoint activity.**

---

