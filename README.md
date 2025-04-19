# Threat-Hunting-Scenario-Data-Exfiltration
![image](https://github.com/user-attachments/assets/bb8cbb85-291f-47cd-a8c1-60cb788b7261)


# Threat Hunt Report: Data Exfiltration
- [Scenario Creation](https://github.com/KBrown233/Threat-Hunting-Scenario-Data-Exfiltration-Data/blob/main/Data%20Exfiltration%20Scenario%20Creation)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)


##  Scenario

This threat hunting scenario investigates suspicious activity by an unknown user account involving unauthorized access to sensitive files and potential data exfiltration attempts using command-line tools such as curl, with evidence suggesting efforts to bypass security controls and transmit data externally.

### High-Level Data Exiltration IoC Discovery Plan

- Investigate unauthorized logins using `DeviceLogonEvents`
- Look for sensitive file access and copy activity in `DeviceFileEvents`
- Search for use of `curl.exe` or similar tools in `DeviceProcessEvents`
- Investigate any network connections made from those processes in `DeviceNetworkEvents`

---

## Steps Taken

### 1. 🕵️Unauthorized Account Logins
Title: Multiple Unauthorized Logins from Unknown Account

Timestamp: April 18, 2025 — From 5:45 PM to 7:41 PM UTC

Action: Detected 6 successful login attempts from an unauthorized account named baduser on device windows-mde-kb.


**Query used to locate events:**

```kql
DeviceLogonEvents
| where DeviceName == "windows-mde-kb"
| where AccountName =~ "baduser"
| project Timestamp, AccountName, LogonType, DeviceName

```
![image](https://github.com/user-attachments/assets/042619bb-08fc-433f-895b-1987abf547c8)




---

### 2. 📁File Access and Copy Events
Title: Sensitive Files Copied by Unauthorized User

Timestamp: April 18, 2025 — 7:41 PM UTC

Action: User baduser accessed and copied files from sensitive folders including a PII-labeled directory.

**Query used to locate event:**

```kql

DeviceFileEvents
| where FolderPath contains "PII" or FolderPath contains "Finance"
| where InitiatingProcessAccountName =~ "baduser"
| project Timestamp, FileName, FolderPath, ActionType, InitiatingProcessFileName
| order by Timestamp desc

```
![image](https://github.com/user-attachments/assets/7cd09ae6-c2af-4028-b6d1-0a9a6acaf646)

>

---

### 3.📤Attempted Data Exfiltration via curl
Title: Unauthorized Data Transfer Attempts Using curl

Timestamp: April 18, 2025 — First at 5:45 PM, Last at 7:46 PM UTC

Action: User baduser issued 12 curl commands targeting internal files like payroll and finance data, suggesting exfiltration attempts.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where FileName =~ "curl.exe"
| where InitiatingProcessAccountName =~ "baduser"
| project Timestamp, ProcessCommandLine, DeviceName
| order by Timestamp desc

```
![image](https://github.com/user-attachments/assets/6bf98e35-1762-4736-8bb1-ec0d13191385)

>

---

### 4. 🌐Network Connections Matching Exfiltration Behavior
Title: Network Activity from curl Executions

Timestamp: April 18, 2025 — Multiple connections between 5:45 PM and 7:46 PM UTC

Action: curl commands were associated with network connections to 127.0.0.1, indicating the data was being staged locally or redirected.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "curl.exe"
| where InitiatingProcessAccountName =~ "baduser"
| project Timestamp, RemoteUrl, RemoteIP, InitiatingProcessCommandLine, DeviceName
| order by Timestamp desc

```
![image](https://github.com/user-attachments/assets/8f02a1e2-1d04-4c3f-80f9-3c32200b64c9)

>

---

## Chronological Event Timeline 

### 1. 🔐Unauthorized Login

April 18, 2025 – 5:45 PM (UTC)

Details: The account baduser, which is not part of the known user directory, successfully logged into the device windows-mde-kb.

### 2. 📂Sensitive File Access and Copy Operations

April 18, 2025 – 7:41 PM (UTC)

Details: The user baduser accessed multiple sensitive files from:

C:\Users\baduser\Documents\PII

C:\Users\baduser\Documents\Finance

Files like sensitive_pii.txt and employee_payroll.xlsx were copied to the desktop.

### 3. 🚨Data Exfiltration Attempt with curl.exe

April 18, 2025 – 7:46 PM (UTC)

Details: The user ran curl.exe to simulate file transfers. Command-line logs show attempted uploads of sensitive files to:

http://internal-fileshare.com/upload

http://payroll-receive.net/data

### 4. 🌐Network Connections from curl.exe 

🕓Immediately After – 7:46 PM (UTC)

Details: curl.exe initiated outbound HTTP connections to the URLs mentioned above, confirming attempted communication with external endpoints.




---

## Summary

On April 18, 2025, suspicious activity was detected on a Windows 10 endpoint (windows-mde-kb) involving an unauthorized user account named baduser. Over the course of two hours, this rogue account successfully logged in multiple times, accessed sensitive files—including Personally Identifiable Information (PII) and financial data—and attempted to exfiltrate that data using curl.exe.

Security telemetry revealed file copy operations involving sensitive directories, followed by outbound HTTP POST requests attempting to upload the data to external servers. Additionally, multiple network connections linked to curl.exe were observed. These actions strongly indicated an intentional data exfiltration attempt.

The threat was contained through rapid isolation of the device, notification of affected users, credential rotations, and initiation of a full forensic investigation.

---

## Responses Taken

To contain and respond to the suspicious activity initiated by the unauthorized account baduser, the following actions were taken:

🛑 Device Isolation:
The affected machine windows-mde-kb was immediately isolated from the network via Microsoft Defender for Endpoint to prevent any further data exfiltration or lateral movement.

🔐 Account Audit and Lockdown:
The rogue account baduser was identified as unauthorized. It was disabled, and a full audit of user accounts was initiated to ensure no other unauthorized access existed.

📁 Data Integrity Verification:
Integrity checks were conducted on the accessed files within the PII and Finance folders to verify no unauthorized changes were made. Backups were reviewed and confirmed intact.

📩 Notification of Affected Stakeholders:
All departments potentially affected by the exposure of sensitive PII and financial files were informed. Compliance and legal teams were also notified for reporting requirements.

🔄 Credential Rotation:
Credentials for users with access to sensitive data were rotated, and elevated access was temporarily restricted pending further review.

🧪 Full Forensic Investigation:
A forensic analysis of windows-mde-kb was launched to determine how the baduser account was created and to identify any additional malicious tools, backdoors, or persistence mechanisms.

📜 Documentation & Lessons Learned:
The incident was fully documented and used to update internal threat detection use cases, response playbooks, and user provisioning procedures to prevent recurrence.

---


