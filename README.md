# Microsoft Defender Incident Investigation

## Phase 2 – Day 34

A SOC investigation exercise focused on investigating Microsoft Defender XDR incidents and validating available endpoint telemetry through Incidents, Alerts, and Advanced Hunting using Kusto Query Language (KQL).

---

## Overview

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

A SOC analyst is investigating a Microsoft Defender environment to determine whether suspicious endpoint activity can be identified.

The investigation begins by reviewing the Incidents and Alerts sections and then moves into Advanced Hunting to search for process, PowerShell, encoded PowerShell, and file activity.

The objective is not only to identify suspicious activity but also to determine whether sufficient telemetry exists to support an investigation.

If the required endpoint telemetry is unavailable, the analyst must document the visibility limitation rather than assume that no suspicious activity occurred.

---

## Investigation Objectives

- Review Microsoft Defender incidents and alerts.
- Understand the available investigation data.
- Access Microsoft Defender Advanced Hunting.
- Review the available hunting schema.
- Use KQL to investigate process activity.
- Hunt for PowerShell execution.
- Hunt for encoded PowerShell commands.
- Review file-event telemetry.
- Determine whether endpoint telemetry is available.
- Document investigation limitations.
- Assess the final investigation outcome based on available evidence.

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

## Skills Demonstrated

- Microsoft Defender XDR navigation
- Incident investigation
- Alert investigation
- Advanced Hunting
- KQL
- Process hunting
- PowerShell hunting
- Encoded PowerShell detection logic
- File-event investigation
- Telemetry assessment
- Evidence-based investigation
- SOC documentation

---

## Conclusion

This lab demonstrated an end-to-end Microsoft Defender investigation workflow from incident and alert review to KQL-based endpoint hunting. Although the environment did not provide incidents, alerts, or endpoint telemetry, the exercise demonstrated the importance of validating telemetry availability before making security conclusions. The investigation followed an evidence-based SOC approach in which empty query results were treated as a visibility limitation rather than proof that no suspicious activity occurred.
