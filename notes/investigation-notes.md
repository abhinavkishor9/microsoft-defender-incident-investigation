# Investigation Notes

## Phase 2 – Day 34: Microsoft Defender Incident Investigation

---

## Investigation Objective

The objective of this investigation was to review the Microsoft Defender XDR incident and alert environment and perform endpoint threat hunting through Advanced Hunting using KQL.

The investigation focused on determining whether process, PowerShell, encoded PowerShell, and file telemetry was available for analysis.

---

## Investigation Scope

The following Defender areas were reviewed:

- Incidents
- Alerts
- Advanced Hunting
- `DeviceProcessEvents`
- `DeviceFileEvents`

Investigation time range:

`Last 7 days`

---

## 1. Incident Review

The Microsoft Defender Incidents page was opened.

The page provided options for:

- Incident name
- Incident ID
- Priority
- Tags
- Severity
- Filter sets

Additional sections included:

- Attack disruptions
- Multi-alert incidents
- Most recent incidents and alerts

### Observation

No incidents were available.

The Attack disruptions section showed:

`None – Last 30 days`

The Multi-alert incidents section showed:

`0% – Last 30 days`

### Finding

No Defender incident was available to investigate.

---

## 2. Alert Review

The Microsoft Defender Alerts page was opened.

The page provided:

- Alert search
- Alert name filtering
- Tags
- Severity
- Investigation state
- Status

### Observation

The page displayed:

`0 Alerts`

### Finding

No individual security alerts were available in the current environment.

---

## 3. Advanced Hunting

Advanced Hunting was opened from the Microsoft Defender investigation and response section.

The interface contained:

- Query editor
- Schema
- Run query
- Query history
- Results panel
- Filters

The investigation window was set to:

`Last 7 days`

---

## 4. Process Telemetry Hunt

### Query

```kusto
DeviceProcessEvents
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName
| sort by Timestamp desc
```

### Purpose

The query was designed to retrieve recent process execution activity and display:

- Timestamp
- Device name
- Process name
- Process command line
- Account name

### Result

`0 items`

### Finding

No process-event telemetry was returned.

---

## 5. PowerShell Hunt

### Query

```kusto
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

### Purpose

The query searched specifically for PowerShell process execution.

The investigation focused on:

- PowerShell executable
- Executing device
- Account
- Command line
- Initiating process

### Result

`0 items`

### Finding

No PowerShell process telemetry was available.

---

## 6. Encoded PowerShell Hunt

### Query

```kusto
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine contains "-EncodedCommand"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

### Purpose

The query searched for PowerShell executions containing the `-EncodedCommand` parameter.

Encoded PowerShell is a useful hunting indicator because encoded commands can make command-line content less immediately visible during an investigation.

### Result

`0 items`

### Finding

No matching encoded PowerShell telemetry was available.

This result does not prove that encoded PowerShell was never executed. It only establishes that no matching telemetry was returned by the queried data source during the selected investigation period.

---

## 7. File Activity Hunt

### Query

```kusto
DeviceFileEvents
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName
| sort by Timestamp desc
```

### Purpose

The query was designed to review file activity and identify:

- File events
- Action type
- Filename
- Folder path
- Initiating process

### Result

`0 items`

### Finding

No file-event telemetry was available.

---

## 8. Evidence Assessment

| Evidence Source | Result |
|---|---|
| Incidents | 0 |
| Alerts | 0 |
| Process Events | 0 |
| PowerShell Events | 0 |
| Encoded PowerShell Events | 0 |
| File Events | 0 |

---

## 9. Investigation Limitation

The primary limitation was the absence of endpoint telemetry.

The Defender investigation interface and Advanced Hunting capability were accessible, but the relevant endpoint data sources returned no records.

Therefore, the investigation could not establish:

- Specific process execution
- PowerShell execution
- Encoded PowerShell execution
- File creation or modification
- Process relationships
- Endpoint-based attack sequence

---

## 10. Evidence Interpretation

The investigation follows this principle:

**No Telemetry does not equal No Activity.**

The correct interpretation is:

**No matching telemetry → Visibility limitation → Insufficient evidence**

This prevents an analyst from making unsupported conclusions.

---

## 11. Final Assessment

### Incidents

No incidents were available.

### Alerts

No alerts were available.

### Endpoint Telemetry

No process or file telemetry was returned.

### PowerShell

No PowerShell telemetry was returned.

### Encoded PowerShell

No matching encoded PowerShell telemetry was returned.

### Investigation Status

**Limited / Insufficient Evidence**

---

## Investigation Conclusion

The Microsoft Defender environment was successfully accessed and the investigation workflow was performed through the Incidents, Alerts, and Advanced Hunting interfaces. However, no incident, alert, process, PowerShell, encoded PowerShell, or file telemetry was available during the investigation window. As a result, the investigation could not confirm or rule out endpoint-based suspicious activity. The appropriate SOC conclusion is therefore an evidence limitation rather than a clean-security determination.
