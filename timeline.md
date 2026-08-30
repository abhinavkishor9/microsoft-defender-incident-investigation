# Investigation Timeline

## Phase 2 – Day 34: Microsoft Defender Incident Investigation

| Step | Investigation Activity | Evidence / Observation | Result |
|---|---|---|---|
| 1 | Opened Microsoft Defender | Defender portal was accessible | Successful |
| 2 | Reviewed Incidents | No incidents were displayed | 0 incidents |
| 3 | Reviewed Alerts | Alerts page displayed 0 alerts | 0 alerts |
| 4 | Opened Advanced Hunting | KQL editor and schema were available | Successful |
| 5 | Reviewed process telemetry | `DeviceProcessEvents` query executed | 0 items |
| 6 | Hunted for PowerShell | PowerShell query executed | 0 items |
| 7 | Hunted for encoded PowerShell | Encoded PowerShell query executed | 0 items |
| 8 | Reviewed file activity | `DeviceFileEvents` query executed | 0 items |
| 9 | Assessed endpoint visibility | No endpoint records were available | Telemetry limitation |
| 10 | Completed investigation assessment | Insufficient endpoint evidence | Investigation limited |

---

## Detailed Investigation Timeline

### Phase 1 – Incident Review

The Microsoft Defender Incidents page was opened as the starting point of the investigation.

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

### Phase 2 – Alert Review

The Microsoft Defender Alerts page was reviewed to determine whether individual security alerts were available.

The page provided filtering options for:

- Alert name
- Tags
- Severity
- Investigation state
- Status

### Observation

The page displayed:

`0 Alerts`

No individual security alerts were available for investigation.

---

### Phase 3 – Advanced Hunting

Advanced Hunting was opened from the Microsoft Defender investigation and response section.

The Advanced Hunting interface provided:

- KQL query editor
- Schema
- Run query
- Results panel
- Query history
- Filters

The investigation time range was set to:

`Last 7 days`

---

### Phase 4 – Process Telemetry Investigation

The following query was executed:

```kusto
DeviceProcessEvents
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName
| sort by Timestamp desc
```

### Result

`0 items`

### Assessment

No process-event telemetry was available for the selected investigation period.

---

### Phase 5 – PowerShell Investigation

The following query was executed:

```kusto
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

### Result

`0 items`

### Assessment

No PowerShell process telemetry was returned.

---

### Phase 6 – Encoded PowerShell Investigation

The following query was executed:

```kusto
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine contains "-EncodedCommand"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

### Result

`0 items`

### Assessment

No matching encoded PowerShell telemetry was returned.

This does not prove that encoded PowerShell was never executed. It establishes only that no matching telemetry was available in the queried dataset during the selected investigation period.

---

### Phase 7 – File Activity Investigation

The following query was executed:

```kusto
DeviceFileEvents
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName
| sort by Timestamp desc
```

### Result

`0 items`

### Assessment

No file-event telemetry was available.

---

## Evidence Timeline

Microsoft Defender Portal

↓

Incidents

↓

0 incidents

↓

Alerts

↓

0 alerts

↓

Advanced Hunting

↓

`DeviceProcessEvents`

↓

0 process events

↓

PowerShell Hunt

↓

0 PowerShell events

↓

Encoded PowerShell Hunt

↓

0 matching events

↓

`DeviceFileEvents`

↓

0 file events

↓

Telemetry Assessment

↓

Insufficient Endpoint Evidence

---

## Final Timeline Assessment

The investigation successfully progressed through the Microsoft Defender Incidents, Alerts, and Advanced Hunting interfaces.

However, no incidents, alerts, process events, PowerShell events, encoded PowerShell events, or file events were available during the selected investigation period.

Therefore, a complete endpoint incident timeline could not be reconstructed.

The final investigation state was:

**Investigation completed with insufficient endpoint telemetry.**

---

## Analyst Note

An empty timeline does not establish that no activity occurred.

It establishes that the available Defender telemetry did not provide events that could be used to reconstruct the activity.

The distinction is:

**No telemetry ≠ No activity**

**No telemetry = Visibility limitation**

This distinction should be preserved in the final SOC investigation record.
