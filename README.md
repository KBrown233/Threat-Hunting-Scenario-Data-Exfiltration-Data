# 🛡️ Insider Threat Hunting Scenario Report

**Incident Title:** Unauthorized Data Access and Exfiltration Attempt by Suspicious Local Account  
**Date of Detection:** April 18, 2025  
**Analyst:** Kevin Brown  
**Toolset Used:** Microsoft Defender for Endpoint (Advanced Hunting / KQL)

---

## 📍 Executive Summary

On April 18, 2025, suspicious activity was detected on the endpoint `windows-mde-kb` involving an unknown local account named `baduser`. This user account was not recognized in the organization's directory and exhibited multiple unauthorized logins, access to sensitive data, and attempted exfiltration using the `curl` command. Activity was detected and investigated using Microsoft Defender for Endpoint with KQL (Advanced Hunting) queries.

---

## 🧾 Timeline of Events

- **First Login by `baduser`:** April 18, 2025 – 1:45 PM (UTC)  
- **Last Login by `baduser`:** April 18, 2025 – 3:41 PM (UTC)  
- **Sensitive File (PII) Accessed:** April 18, 2025 – 3:41 PM (UTC)  
- **First `curl` Exfil Attempt:** April 18, 2025 – 1:45 PM (UTC)  
- **Last `curl` Exfil Attempt:** April 18, 2025 – 3:46 PM (UTC)  
- **Simulated Network Destination:** `127.0.0.1`  

---

## 🔍 KQL Queries & Findings

### 1. ✅ Unauthorized Logins

Multiple successful logins by a non-corporate account (baduser) were detected. These logins occurred six times between 1:45 PM and 3:41 PM UTC. The device involved was windows-mde-kb, a managed corporate system. This immediately flagged as suspicious due to the unknown account.

```kql
DeviceLogonEvents
| where DeviceName == "windows-mde-kb"
| where AccountName =~ "baduser"
| project Timestamp, AccountName, LogonType, DeviceName

---

### 2. 






