# Lab 02 — Detecting DNS Tunneling with Sysmon and Sigma

**Objective:** Identify DNS-based command-and-control or data-exfiltration channels using Sysmon Event ID 22 (DNS query) and behavioral heuristics.

**Tools:** Sysmon (with DNS query logging enabled), Splunk/Sentinel, Sigma

---

## 1. Background

DNS tunneling abuses the DNS protocol to smuggle data (C2 commands, exfiltrated files) inside DNS queries and responses, because DNS is rarely blocked outbound. Typical indicators:

- High volume of queries to a single parent domain
- High-entropy / randomized subdomains (e.g., `a8f3k2z9.evil-domain.com`)
- Heavy use of `TXT`, `NULL`, or `CNAME` record types (larger payload capacity than `A` records)
- Long subdomain labels close to the 63-character DNS label limit
- Queries originating from unexpected processes (not a browser or known DNS client)

## 2. Enabling Visibility

Sysmon config snippet to capture DNS queries (Event ID 22, requires Sysmon 11+):

```xml
<DnsQuery onmatch="exclude">
  <QueryName condition="end with">.microsoft.com</QueryName>
</DnsQuery>
```

This captures all DNS queries except a defined allowlist, giving process-to-domain visibility that plain DNS server logs lack.

## 3. Detection Logic (SPL example)

```spl
index=sysmon EventCode=22
| rex field=QueryName "^(?<subdomain>[^.]+)\.(?<domain>.+)$"
| eval label_len=len(subdomain)
| stats count avg(label_len) as avg_label_len values(Image) as querying_process by domain
| where count > 200 AND avg_label_len > 30
| sort - count
```

Flags any second-level domain receiving 200+ queries with abnormally long subdomain labels — a strong tunneling signal.

## 4. Sigma Rule

```yaml
title: Possible DNS Tunneling - High Volume High Entropy Subdomains
status: experimental
logsource:
  category: dns_query
  product: windows
detection:
  selection:
    QueryType: 'TXT'
  timeframe: 15m
  condition: selection | count() by QueryName_domain > 150
falsepositives:
  - Legitimate telemetry/update-check agents using TXT record polling
  - CDN or anti-spam services performing high-volume TXT lookups
level: high
tags:
  - attack.command_and_control
  - attack.t1071.004
  - attack.exfiltration
  - attack.t1048.003
```

## 5. Investigation Checklist

1. Identify the querying process (`Image` field in Sysmon Event 22) — is it a browser, a known agent, or something unrecognized/unsigned?
2. Check the destination domain's registration date and reputation — newly registered or low-reputation domains are higher risk.
3. Decode a sample of the subdomain labels — Base32/Base64-encoded data is a strong tunneling confirmation.
4. Correlate with proxy/firewall logs — is the same host also making unusual outbound HTTP(S) connections?
5. If confirmed malicious: block the domain at the DNS resolver/firewall, isolate the host, and collect a memory/disk image for forensics.

## 6. Common False Positives

- Endpoint management, EDR, or antivirus agents using DNS TXT records for lightweight telemetry or "phone home" checks (see also: `soc-ticket-portfolio/TICKET-003`).
- CDN and anti-spam infrastructure that legitimately performs high query volumes to a single domain.

## 7. Key Takeaway

DNS tunneling detection is fundamentally a **volume + entropy + process-context** problem — no single field is reliable alone. Combining Sysmon's process-to-DNS-query visibility with subdomain entropy scoring dramatically reduces false positives compared to volume-only thresholds.
