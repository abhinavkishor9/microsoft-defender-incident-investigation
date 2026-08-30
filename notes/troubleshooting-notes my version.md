# Troubleshooting Notes

## 1. No Incidents Displayed

### Observation

The Microsoft Defender Incidents page displayed no available incidents.

### Expected

Normally, this page may contain:

- Incident names
- Incident IDs
- Severity
- Priority
- Status
- Detection information

### Actual Result

`No incidents available`

### Assessment

This was treated as an environmental observation rather than a portal failure.

No fictional incident was created for the investigation.

---

## 2. Alerts Page Displayed 0 Alerts

### Observation

The Alerts page displayed:

`0 Alerts`

### Assessment

There were no available alerts to investigate.

The absence of alerts does not prove that the environment has never experienced suspicious activity.

It only establishes that no alerts were available in the current Defender environment.

---

## 3. Advanced Hunting Was Accessible

### Observation

Advanced Hunting opened successfully.

The following capabilities were available:

- Query editor
- Schema
- Run query
- Results
- Query history
- Filters

### Assessment

The Advanced Hunting interface was functioning normally.

The problem was not query execution.

The limitation was the absence of endpoint telemetry.

---

## 4. Process Query Returned 0 Items

### Query

```kusto
DeviceProcessEvents
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName
| sort by Timestamp desc
```

### Result

`0 items`

### Assessment

No process telemetry was available for the selected investigation period.

---

## 5. PowerShell Query Returned 0 Items

### Query

```kusto
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

### Result

`0 items`

### Assessment

No PowerShell telemetry was returned.

This should not be interpreted as proof that PowerShell was not executed.

---

## 6. Encoded PowerShell Query Returned 0 Items

### Query

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

No matching encoded PowerShell events were available.

The correct interpretation is:

**No matching telemetry**

rather than:

**Encoded PowerShell did not occur**

---

## 7. File Query Returned 0 Items

### Query

```kusto
DeviceFileEvents
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName
| sort by Timestamp desc
```

### Result

`0 items`

### Assessment

No file-event telemetry was available.

This prevented correlation between process activity and file activity.

---

## 8. Investigation Window

Advanced Hunting was configured for:

`Last 7 days`

Therefore, the results represent the telemetry available within the selected investigation window.

An empty result should be interpreted within that scope.

---

## 9. Telemetry Limitation

The primary troubleshooting finding was:

**Defender portal accessible → Advanced Hunting accessible → Queries executed successfully → Endpoint tables returned 0 records**

This indicates that the investigation limitation was related to data availability rather than inability to execute KQL queries.

---

