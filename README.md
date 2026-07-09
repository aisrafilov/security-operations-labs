# Security Operations Labs

Hands-on detection engineering labs covering Windows Event Logs, Sysmon, SIEM query languages (SPL/KQL), and Sigma rules.

## Labs

| Lab | Focus | Techniques |
|---|---|---|
| [Lab 01](labs/lab-01-windows-4625-brute-force-detection.md) | Brute-force detection via Windows Event ID 4625 | T1110.001 |
| [Lab 02](labs/lab-02-dns-tunneling-detection.md) | DNS tunneling detection via Sysmon Event ID 22 | T1071.004, T1048.003 |

Each lab includes: background, detection logic in both SPL and KQL where applicable, a Sigma rule, an investigation checklist, and known false-positive patterns.

## Related

See [`attack-to-detection`](https://github.com/aisrafilov/attack-to-detection) for MITRE ATT&CK-mapped versions of this detection logic, and [`soc-ticket-portfolio`](https://github.com/aisrafilov/soc-ticket-portfolio) for real-world tickets generated from these detections.
