# Lab 01: Windows Failed Logins

## Objective
Investigate repeated failed login attempts followed by successful authentication.

## Scenario
A SIEM alert triggered after many Windows Event ID 4625 events were observed for one user account from a single external IP address.

## Expected Analysis
- Count failed logins by account and source IP
- Identify whether a successful login followed the failures
- Determine whether the source IP is expected
- Map to MITRE ATT&CK

## MITRE ATT&CK
- T1110 Brute Force
- T1078 Valid Accounts

## Outcome
Escalate if successful login is confirmed and user cannot validate the activity.
