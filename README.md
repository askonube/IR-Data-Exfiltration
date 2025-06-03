# IR-Data-Exfiltration

# 🛡️ Insider Threat Hunting: Suspected Data Exfiltration from PIP'd Employee

## Overview

This project documents a cybersecurity incident response simulation involving a suspected insider threat. A user placed on a performance improvement plan was observed exhibiting behavior that could indicate data exfiltration. The investigation was conducted using **Microsoft Defender for Endpoint (MDE)** data tables to identify, analyze, and respond to suspicious file archiving activity.

---

## 🧭 1. Preparation

### 🎯 Goal:
Set up the hunt by defining what you're looking for.

### Scenario:
An employee named John Doe, working in a sensitive department, was placed on a performance improvement plan (PIP). After exhibiting emotional behavior, management became concerned that John might attempt to exfiltrate proprietary information.

### Hypothesis:
John has admin rights on his corporate device `alex-mde-test`, including unrestricted PowerShell usage. He may compress and archive files and upload them to an external source.

---

## 🗃️ 2. Data Collection

### 🎯 Goal:
Gather relevant data from logs, network traffic, and endpoints.

### Action:
Searched the following Microsoft Defender for Endpoint tables:

- `DeviceFileEvents`
- `DeviceProcessEvents`
- `DeviceNetworkEvents`

#### Initial Findings:
Located multiple instances of ZIP file creation and movement to a `backup` directory.

```kql
DeviceFileEvents
| where DeviceName == "alex-mde-test"
| where FileName contains "zip"
| sort by Timestamp desc
```

![image](THIS IS A SCREENSHOT OF THE QUERIES FROM DEVICEFILEEVENTS)


---

## 📊 3. Data Analysis

### 🎯 Goal
Analyze data to test your hypothesis.

### Findings
- Used a specific ZIP file creation timestamp to investigate surrounding events.

### Observed
- PowerShell silently installed 7-Zip.
- 7-Zip was used to archive employee data.

```kql
let VMName = "alex-mde-test";
let specificTime = datetime(2025-04-09T22:17:16.6780857Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
```

![image](THIS IS A SCREENSHOT OF THE QUERIES FROM DEVICEPROCESSEVENTS)


### Exfiltration Check

No signs of external data transfer found in `DeviceNetworkEvents`.

```kql
DeviceNetworkEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == "alex-mde-test"
| order by Timestamp desc
```

---

## 🕵️‍♂️ 4. Investigation

### 🎯 Goal
Investigate any suspicious findings.

### MITRE ATT&CK TTPs

| Tactic          | Technique                  | Description                                               |
|-----------------|----------------------------|-----------------------------------------------------------|
| Execution       | PowerShell (T1086)         | Used to silently install and execute 7-Zip                |
| Persistence     | Scheduled Task/Job (T1053) | Potential persistence vector for automated archiving      |
| Defense Evasion | Masquerading (T1036)       | Use of 7-Zip may mask malicious intent                    |
| Collection      | Data Staged (T1074)        | Data prepared in ZIP archive potentially for exfiltration |


---

## 🚨 5. Response

### 🎯 Goal  
Mitigate any confirmed threats.

### Actions Taken
- All findings were escalated to John’s manager for HR handling.  
- No evidence of data exfiltration was found.  
- Recommended monitoring of John’s device for further activity.

---

## 📝 6. Documentation

### 🎯 Goal  
Record your findings and learn from them.

### 📚 What was Documented
- Query logs with timestamps  
- Observed file and process behavior  
- MITRE ATT&CK mapping  
- Management escalation actions

---

## 🔄 7. Improvement

### 🎯 Goal  
Improve your security posture or refine your methods.

### Prevention Recommendations:
- **PowerShell Logging & Restrictions**: Enable Script Block and Module Logging, and apply Constrained Language Mode.  
- **Least Privilege**: Restrict unnecessary admin rights and software installation privileges.  
- **Application Whitelisting**: Prevent unauthorized tools like 7-Zip from being silently installed.  
- **Behavioral Alerts**: Create alerts for:
  - PowerShell installing programs
  - Mass ZIP file creation
  - Admin user archiving sensitive files

### ⚙️ Hunting Process Enhancements:
- Automate correlation between `DeviceFileEvents` and `DeviceProcessEvents`
- Add scheduled process hunting based on timestamp-based anomalies
- Improve user behavior baselining (e.g., who normally uses 7-Zip?)

---

## 📌 Summary

This investigation highlights how behavioral analysis and endpoint telemetry can uncover early signs of insider threats. Even without confirmed exfiltration, the act of staging data for compression on a sensitive employee’s device warrants serious scrutiny.



