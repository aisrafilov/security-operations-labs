# KQL: Failed Logins Followed by Success

```kql
SecurityEvent
| where EventID in (4625, 4624)
| summarize Failed=countif(EventID == 4625), Success=countif(EventID == 4624) by Account, IpAddress, bin(TimeGenerated, 30m)
| where Failed >= 10 and Success >= 1
| order by Failed desc
```
