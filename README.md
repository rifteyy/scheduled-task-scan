# Scheduled Task Scanner
Advanced scanner for unsigned, suspicious, malware, invalid scheduled tasks and more coded in Batch.

Logs are saved in the same folder the script is running from in file `scheduled_tasks_scan[index]`.

Requires admin permissions to run.

---

## 🛠️ Features
- Display safe entries (0 detections on VirusTotal)
- Display suspicious entries and their command-line arguments (>0 detections on VirusTotal)
- Display unsigned entries
- Display heuristic detected entries and their command-line arguments  (any entry that invokes `mshta powershell bitsadmin curl wscript cscript certutil cmd msbuild msxsl regsvr32 regasm`)
- Display invalid tasks (tasks that are pointing to a file path that does no longer exist)
- Display pathless tasks (tasks that do not have a file path to start)
- Display unknown entries and their command-line arguments (tasks that start a file path that was identified as a file path using regex, but was not found)
- Display submitted entries and their command-line arguments (tasks file path that was submitted to VirusTotal, recommended to rescan after few minutes)

---

## 🔎 Scan types
- `quick`: Will scan tasks in folder `%windir%\System32\Tasks`, but not in subfolders
- `full`: Will use `schtasks` to identify all known Tasks in your system and scan them

---

## 🔑 Usage
1) To select a scan type, edit the script in Notepad and look at line number 5
2) Download the `sigcheck.exe` and `latest.bat` and keep it in the same folder
3) Right-click the `latest.bat` file and select `Run as administrator`
4) Confirm the UAC and the smart-screen warning
5) Wait till the scan finishes (will take longer if you chose full scan)
6) Open the log file in same folder named `scheduled_tasks_scan[index]` and see the results

---

## Log example
```
Scheduled task scan - 20/12/2024 19:04:37.36
https://github.com/rifteyy/scheduled-task-scan

Scan mode: quick
Ran from: C:\Users\admin\Desktop\
Detected: 3

Safe entries (5) - these entries were scanned by VT and heuristic analyze and are safe:
- Task name: \CCleaner Update "C:\Program Files\CCleaner\CCUpdate.exe"
- Task name: \CCleanerCrashReporting "C:\Program Files\CCleaner\CCleanerBugReport.exe"
- Task name: \CreateExplorerShellUnelevatedTask "C:\Windows\explorer.exe"
- Task name: \MicrosoftEdgeUpdateTaskMachineCore{9E4A958F-0E40-40A9-B5F4-CCF390E46BB7} "C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe"
- Task name: \MicrosoftEdgeUpdateTaskMachineUA{BAAEC913-F5F5-467C-989B-F707EC8B3F35} "C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe"

Suspicious entries (2) - these entries have a minimum 1 detection on VirusTotal:
- Task name: \update-S-1-5-21-594799317-1564658908-862903225-1001 "C:\Program Files (x86)\Skillbrains\Updater\Updater.exe" - Detection: 2/76
  - Full command: "C:\Program Files (x86)\Skillbrains\Updater\Updater.exe -runmode=checkupdate"
- Task name: \update-sys "C:\Program Files (x86)\Skillbrains\Updater\Updater.exe" - Detection: 2/76
  - Full command: "C:\Program Files (x86)\Skillbrains\Updater\Updater.exe -runmode=checkupdate"

Unsigned entries (0) - these entries do not have a valid digital signature:

Heuristic detections (1) - tasks that abuse commonly used EXE files to download/run malware:
- Task name: \HrDetection - "powershell.exe"
  - Full command: "powershell.exe -windowstyle Hidden "payload.exe""

Invalid tasks (1) - these entries can be deleted as the file they are supposed to start does not exist:
- Task name: \LaunchHone "C:\Users\admin\AppData\Local\Programs\Hone\Hone.exe"

Pathless tasks (0) - these entries do not have a file to launch:

Unknown entries (0) - these entries could not be analyzed:

Submitted entries (0) - these entries were submitted to analyze on VirusTotal:
```
