# Threat Hunting with Splunk

![Splunk Logo](https://upload.wikimedia.org/wikipedia/commons/f/f3/Splunk_logo.png)

## Introduction
This repository contains a collection of **Splunk queries** designed for **threat hunting** in Windows environments.  
The goal is to help analysts detect **malicious activity**, **lateral movement**, **persistence techniques**, and **potential indicators of compromise (IOCs)** using logs from Windows Sysmon, PowerShell, and other event sources.

All queries are tested against simulated threat data and can be adapted to your environment.

---
## 1. PowerShell & Process/File Creation

**Detects suspicious PowerShell activity and process/file creation events.**

```spl
(index="windows_powershell") 
OR (index="windows_sysmon" FileCreate) 
OR (index="windows_sysmon" ProcessCreate)
| table  _time, CommandLine, TargetFilename, ParentImage, Image
```
---
##  2. Finding Potential Malware
### 2.1 Potential File IOCs (Parent-Child Process Anomalies)
```spl
index=* AND ParentImage=* 
| where like(ParentImage, "%Users%") 
| where NOT like(ParentImage, "%OneDrive%OneDrive%.exe%") 
| where NOT like(ParentImage, "%Microsoft VS Code%Code.exe%") 
| table _time, host, User, ParentImage, Image, CommandLine  
| sort - _time
```

### 2.2 Files with Zone.Identifier (Downloaded Files)
```spl
index=* "Zone.Identifier"  
| table _time, host, User, TargetFilename 
| sort - _time
```

### 2.3 Suspicious Non-Microsoft Binaries
```spl
index=* AND Company=* 
Company!="Microsoft Corporation" Company!="VMware, Inc." Company!="Microsoft Corp." 
ParentImage!="C:\\Windows\\System32\\svchost.exe" 
| table _time, host, User, Image, CommandLine, Company 
| sort - _time
```
---
## 3. Executing Potential Malware Files
Execution of binaries from user directories via PowerShell or CMD.
```spl
index=* AND ParentImage=* 
| where match(Image, "(?i).*Users.*") 
| where match(ParentImage, "(?i).*(powershell\.exe|cmd\.exe)") 
| where NOT match(Image, "(?i).*Users.*OneDrive.*\.exe.*") 
| where NOT match(ParentImage, "(?i).*Microsoft\s+VS\s+Code.*Code\.exe.*") 
| table _time, host, User, ParentImage, Image, CommandLine 
| sort - _time
```
---
## 4. Files Generating Network Events
Identifies executables initiating network connections from unusual paths.

```spl
index=* TaskCategory=Network* 
| where NOT ( like(Image, "C:%Program Files%")  
OR like(Image, "%Local%Microsoft%OneDrive%") 
OR like(Image, "%Windows%ystem32%") )
| stats count by Image
```

---

## 5. Mimikatz & Credential Theft
```spl
index=* (CommandLine="*sekurlsa*" OR CommandLine="*logonpasswords*" OR Image="*mimikatz.exe*") 
| table _time, host, User, CommandLine, Description, OriginalFileName 
| sort - _time
```
---
## 6. Network & Remote Activity
### 6.1 Potential Attacker IP (Private Range Example)

```spl
index=* AND DestinationIp 
| where match(DestinationIp, "(?i).*192\.168\.*") 
| table _time, host, DestinationIp, DestinationPort, Image 
| sort - _time
```

### 6.2 Remote Service Creation

```spl
index=* EventCode=4697
```

### 6.3 Services Installed

```spl
index=* AND EventCode=7045 
| table _time, host, Service_Name, Service_File_Name, Service_Start_Type 
| sort - _time
```

### 6.4 NTLM Logon from Non-DC Hosts

```spl
index=* EventCode=4624 AND Logon_Process="NtlmSsp" AND NOT (host="DC1") 
| table _time, host, Account_Name, Logon_Type, Logon_Process 
| sort - _time
```
---

## 7. Persistence Mechanisms
### 7.1 New Accounts & Group Modifications

```spl
index=* AND (EventCode=4728 OR EventCode=4732 OR EventCode=4720) 
| table _time, host, result, New_Account_Account_Name, Account_Name, SAM_Account_Name, Group_Name 
| sort - _time
```

### 7.2 Scheduled Tasks

```spl
index=* AND EventCode=106
```

### 7.3 Registry-Based Persistence

```spl
index=* TaskCategory=Process* "C:\\windows\\tasks\\*" 
| table _time, host, ParentImage, CommandLine 
| sort - _time
```
---

## 8. File Types Triggering Net-NTLMv2 Auth Requests

```spl
index="*" ("*.rtf" OR "*.scf" OR "*.url" OR "*.wmx" OR "*.accdb" OR "*.pub" OR "*.asx" OR "*.doc" OR "*.docx" OR "*.xls" OR "*.xlsx") 
| table _time, TargetFilename, Image, User
```
---

## 9. Time Range Filtering Example

```spl
index=* earliest="07/24/2024:00:00:00" latest="07/25/2024:11:11:59"

```
---

⚠  **Disclaimer**

These queries are examples and may need adjustments for your specific environment.
Always validate results before taking action.