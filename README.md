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
