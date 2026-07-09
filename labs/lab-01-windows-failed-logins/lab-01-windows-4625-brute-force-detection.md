# Lab 01 — Detecting Brute-Force Activity via Windows Event ID 4625

**Objective:** Build a detection and investigation workflow for brute-force login attempts using native Windows Security event logs.

**Tools:** Windows Event Viewer, Sysmon, Splunk (or any SIEM), KQL/SPL

---

## 1. Background

Event ID 4625 ("An account failed to log on") is logged on every failed authentication attempt on a Windows host. On its own, a single 4625 event is noise — but a *pattern* of 4625 events (many failures, short time window, multiple usernames, single source) is a strong brute-force indicator.

Key fields to extract from each 4625 event:

| Field | Meaning |
|---|---|
| `TargetUserName` | Account the attacker attempted to authenticate as |
| `IpAddress` | Source IP of the logon attempt (populated for network logons) |
| `LogonType` | 3 = network, 10 = RDP — critical for scoping attack surface |
| `FailureReason` / `Status` / `SubStatus` | Why the logon failed (bad password vs. account disabled vs. account locked) |
| `WorkstationName` | Hostname reported by the source (attacker-controlled, use with caution) |

## 2. Detection Logic (SPL example)

```spl
index=windows EventCode=4625 LogonType=10
| bin _time span=10m
| stats count dc(TargetUserName) as unique_usernames values(TargetUserName) as attempted_users by _time, IpAddress, Computer
| where count > 20 AND unique_usernames > 5
| sort - count
```

This flags any 10-minute window where a single source IP generated more than 20 failed RDP logons against more than 5 distinct usernames — the username-spray pattern typical of automated brute-force tools.

## 3. Detection Logic (KQL / Sentinel example)

```kql
SecurityEvent
| where EventID == 4625 and LogonType == 10
| summarize FailCount = count(), DistinctUsers = dcount(TargetUserName) by IpAddress, bin(TimeGenerated, 10m)
| where FailCount > 20 and DistinctUsers > 5
| order by FailCount desc
```

## 4. Investigation Checklist

When this rule fires, an analyst should:

1. Confirm the source IP is external / unexpected (rule out internal misconfigured services or expired scheduled-task credentials).
2. Check for a corresponding **Event ID 4624** (successful logon) from the same source IP — did the brute-force succeed?
3. If successful, pivot into that account's subsequent activity (new process creation, new logon sessions, lateral movement).
4. Check firewall/NSG rules — is the exposed service intentionally internet-facing, or is this a misconfiguration?
5. Contain: block source IP, disable/reset affected account(s) if any authentication succeeded, enable account lockout policy if not already active.

## 5. Common False Positives

- Expired service account credentials retried by a scheduled task (single username, high volume, internal source).
- Misconfigured mobile device or legacy application repeatedly retrying stale cached credentials.
- Security scanning tools performing authenticated vulnerability scans without correct credentials configured.

## 6. Sigma Rule

```yaml
title: Potential RDP Brute Force via Event 4625
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
    LogonType: 10
  timeframe: 10m
  condition: selection | count() by IpAddress > 20
falsepositives:
  - Scheduled tasks with expired credentials
  - Authenticated vulnerability scanners
level: high
tags:
  - attack.credential_access
  - attack.t1110.001
```

## 7. Key Takeaway

Single-event alerting on 4625 is too noisy for production use. Effective brute-force detection requires **aggregation** (count + distinct-user threshold over a time window) and **correlation** with 4624 to determine whether containment or just monitoring is required.
