<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/TheBenjaminCole/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "bcole" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2026-01-14T17:09:23.0990778Z`. These events began at `2026-01-14T16:38:30.2908254Z`.

**Query used to locate events:**

```kql
 DeviceFileEvents
| where FileName contains "tor"
| where DeviceName == "mde-lab-test-be"
| where InitiatingProcessAccountName == "bcole"
| where TimeGenerated >= datetime(2026-01-14T16:38:30.2908254Z)
| order by TimeGenerated desc
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1355" height="491" alt="image" src="https://github.com/user-attachments/assets/1ce36eb8-7e9f-4e2f-bf83-7eb9e505d489" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows". Based on the logs returned, at `2026-01-14T16:51:59.9022141Z`, an employee on the "mde-lab-test-be" device ran the file `tor-browser-windows-x86_64-portable-15.0.4.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "mde-lab-test-be"
| where ProcessCommandLine startswith "tor-browser-windows"
| project TimeGenerated, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1656" height="105" alt="image" src="https://github.com/user-attachments/assets/f2b89208-87a3-4aca-a8ee-318f4f02b9de" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "bcole" actually opened the TOR browser. There was evidence that they did open it at `2026-01-14T16:52:39.1428052Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "mde-lab-test-be"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe", "start-tor-browser.exe", "tor-browser-portable.exe")
| project TimeGenerated, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by TimeGenerated desc 
```
<img width="1645" height="465" alt="image" src="https://github.com/user-attachments/assets/12920cee-0015-4aa9-a5d6-62f65fccfefa" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2026-01-14T16:53:14.7613209Z`, an employee on the "mde-lab-test-be" device successfully established a connection to the remote IP address `127.0.0.1` on port `9150`. The connection was initiated by the process `firefox.exe`, located in the folder `C:\Users\bcole\Desktop\Tor Browser\Browser\firefox.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
|where DeviceName == "mde-lab-test-be"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150")
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
```
<img width="1655" height="100" alt="image" src="https://github.com/user-attachments/assets/db42aeb3-3d87-4500-8cbe-c2dfefc0f2f3" />

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2026-01-14T16:38:30.2908254Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-15.0.4.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\bcole\Downloads\tor-browser-windows-x86_64-portable-15.0.4.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2024-11-08T22:16:47.4484567Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.4  /S`
- **File Path:** `C:\Users\bcole\Downloads\tor-browser-windows-x86_64-portable-15.0.4.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2026-01-14T16:52:39.1428052Z`
- **Event:** User "bcole" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\bcole\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2026-01-14T16:53:14.7613209Z`
- **Event:** A network connection to IP `127.0.0.1` on port `9150` by user "bcole" was established using `firefox.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `firefox.exe`
- **File Path:** `c:\users\bcole\desktop\tor browser\browser\firefox.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2026-01-14T16:53:08.0450041Z` - Connected to `94.230.208.148` on port `443`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "bcole" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2026-01-14T17:09:23.0990778Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\bcole\Documents\tor-shopping-list.txt`

---

## Summary

The user "bcole" on the "mde-lab-test-be" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `mde-lab-test-be` by the user `bcole`. The device was isolated, and the user's direct manager was notified.

---
