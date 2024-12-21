@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

rem To scan all scheduled tasks - set "scan=full"
rem To scan basic tasks just in direct folder, no subfolders - set "scan=quick"
set "scan=quick"

title
for /F "tokens=1,2 delims=#" %%a in ('"prompt #$H#$E# & echo on & for %%b in (1) do rem"') do (
  set "ESC=%%b"
)
set "task_index=0"
"%windir%\system32\net.exe" session >nul 2>&1
if not !errorlevel! equ 0 (
	echo=Error: Admin permissions are required to run this script.
	pause
	exit /b 1
)

if "!scan!"=="quick" (
	set "command=dir "%windir%\system32\tasks" /b /a:-d"
)
if "!scan!"=="full" (
	set "command=%windir%\System32\schtasks.exe /query /fo LIST /v | findstr.exe "TaskName:""
)
for /f "delims=" %%A in ('!command!') do (
	set "tmp=%%A"
	set "task_name=!tmp:Taskname:                             =!"
	for /f "delims=" %%B in ('%windir%\System32\schtasks.exe /query /tn "!task_name!" /fo CSV /v') do (
		for /f "delims=, tokens=1-20" %%a in ('%windir%\System32\schtasks.exe /query /tn "!task_name!" /fo CSV /v') do (
			if "!skip_line!"=="true" (
				if not "!task[%%~b]!"=="true" (
					set /a "task_index+=1"
					set "skip_line=false"
					set "task[%%~b]=true"
					set "task_name[!task_index!]=%%~b"
					set "schedule_type[!task_index!]=%%~s"
					echo=
					echo=!ESC![1;1HQuerying task "%%~b"...                                                                                                                         
				)
			)
		set "skip_line=true"
		)
		if not "!task[%%~b]!"=="true" for /F "delims=" %%A in ('%windir%\System32\schtasks.exe /query /tn "!task_name!" /xml ^| %windir%\System32\findstr.exe /i "<Command>"') do (	
			set "line=%%A"
			set "line=!line:      <Command>=!"
			set "file_path=!line:</Command>=!"
			set "file_path[!task_index!]=!file_path!"
		)
	)
)
for /l %%A in (1 1 !task_index!) do (
	for /f "delims=" %%B in ('echo^=!file_path[%%A]!') do (
		set "file_path[%%A]=%%B"
		echo=!ESC![1;1HUnpacking file paths from task "!task_name[%%A]!"...                                                                 
	)
)
for %%A in (safe suspicious unsigned signed invalid_entry heuristic_detections unknown_path pathless_entry submitted) do set "%%A=0"
for /l %%# in (1 1 !task_index!) do (
	set "file_path[%%#]=!file_path[%%#]:"=!"
	set "fpath=!file_path[%%#]!"
	echo=!ESC![1;1HScanning task "!task_name[%%#]!"...                                                                               
	if "!fpath!"=="" (
		set /a "pathless_entry+=1"
		for %%@ in ("!pathless_entry!") do (
			set "pathless_entry_taskname[%%~@]=!task_name[%%#]!"
			set "pathless_entry_filepath[%%~@]=!fpath!"
		)
	) else (
	if not exist "!fpath!" (for %%{ in ("mshta" "powershell" "bitsadmin" "curl" "wscript" "cscript" "certutil" "cmd" "msbuild" "msxsl" "regsvr32" "regasm") do if not "!fpath!"=="!fpath:%%~{=!" (
		set /a "heuristic_detections+=1"
		for %%@ in ("!heuristic_detections!") do (
			set heur=true
			set "heuristic_entry_taskname[%%~@]=!task_name[%%#]!"
			set "heuristic_entry_filepath[%%~@]=!fpath!"
		))
	if not "!heur!"=="true" (
		echo=!fpath!| %windir%\System32\findstr.exe /R "^[a-zA-Z]:\\.*\..*$" >nul
		if !errorlevel! equ 1 (
			set /a "unknown_path+=1"
			for %%@ in ("!unknown_path!") do (
				set "unknown_entry_taskname[%%~@]=!task_name[%%#]!"
				set "unknown_entry_filepath[%%~@]=!fpath!"
			)
		) else (
			set /a "invalid_entry+=1"
			for %%@ in ("!invalid_entry!") do (
				set "invalid_entry_taskname[%%~@]=!task_name[%%#]!"
				set "invalid_entry_filepath[%%~@]=!fpath!"
			)
		)	
	) else set "heur=false"
	) else (
		for /f "delims=: tokens=1,*" %%A in ('sigcheck.exe -accepteula -nobanner -vt -vs "!file_path[%%#]!"') do (
			set "val=%%A"
			set "val2=%%B"
			if "!val:	=!"=="Verified" (
				if "!val2:	=!"=="Unsigned" (
					set "unsigned+=1"
					for %%@ in ("!unsigned!") do (
						set "unsigned_taskname[%%~@]=!task_name[%%#]!"
						set "unsigned_filepath[%%~@]=!file_path[%%#]!"
						set "unsigned_schedule_type[%%~@]=!schedule_type[%%#]!"
					)
				) else (
					set /a "signed+=1"
					for %%@ in ("!signed!") do (
						set "signed_taskname[%%~@]=!task_name[%%#]!"
						set "signed_filepath[%%~@]=!fpath!"
						set "signed_schedule_type[%%~@]=!schedule_type[%%#]!"
					)
				)
			)
			if "!val:	=!"=="VT detection" (
				set "vt_detection[%%#]=!val2:	=!"
				if "!!vt_detection[%%#]!"=="Submitted" (
					set /a "submitted+=1"
					for %%@ in ("!submitted!") do (
						set "submitted_taskname[%%~@]=!task_name[%%#]!"
						set "submitted_filepath[%%~@]=!fpath!"
					)
				) else for /f "delims=/ tokens=1,2" %%a in ("!vt_detection[%%#]!") do (
					if "%%a" geq "1" (
						set /a "suspicious+=1"
						for %%@ in ("!suspicious!") do (
							set "suspicious_taskname[%%~@]=!task_name[%%#]!"
							set "suspicious_filepath[%%~@]=!fpath!"
							set "suspicious_schedule_type[%%~@]=!schedule_type[%%#]!"
							set "suspicious_detection[%%~@]=!vt_detection[%%#]!"
						)
					) else (
						set /a "safe+=1"
						for %%@ in ("!safe!") do (
							set "safe_taskname[%%~@]=!task_name[%%#]!"
							set "safe_filepath[%%~@]=!fpath!"
							set "safe_schedule_type[%%~@]=!schedule_type[%%#]!"
						)
					)
				)
			)
		)
	)
))
set /a "detections=suspicious + heuristic_detections"
set "log_number=0"
:log_name
if exist "scheduled_tasks_scan[!log_number!].txt" (
	set /a "log_number+=1"
	goto :log_name
)

(
echo=Scheduled task scan - !date! !time!
echo=https://github.com/rifteyy/scheduled-task-scan
echo=
echo=Scan mode: !scan!
echo=Ran from: %~dp0
echo=Detected: !detections!
echo=
echo=Safe entries ^(!safe!^) - these entries were scanned by VT and heuristic analyze and are safe:
for /l %%A in (1 1 !safe!) do (
	echo=- Task name: !safe_taskname[%%A]! "!safe_filepath[%%A]!"
)
echo=
echo=Suspicious entries ^(!suspicious!^) - these entries have a minimum 1 detection on VirusTotal:
for /l %%A in (1 1 !suspicious!) do (
	echo=- Task name: !suspicious_taskname[%%A]! "!suspicious_filepath[%%A]!" - Detection: !suspicious_detection[%%A]!
	for /F "delims=" %%# in ('%windir%\System32\schtasks.exe /query /tn "!suspicious_taskname[%%A]!" /xml ^| %windir%\System32\findstr.exe /i "<Arguments>"') do (	
		set "line=%%#"
		set "line=!line:      <Arguments>=!"
		set "line=!line:</Arguments>=!"
		echo   - Full command: "!suspicious_filepath[%%A]! !line:~0,-1!"
	)
)
echo=
echo=Unsigned entries ^(!unsigned!^) - these entries do not have a valid digital signature:
for /l %%A in (1 1 !unsigned!) do (
	echo=- Task name: !unsigned_taskname[%%A]! "!unsigned_filepath[%%A]!"
)
echo=
echo=Heuristic detections ^(!heuristic_detections!^) - tasks that abuse commonly used EXE files to download/run malware:
for /l %%A in (1 1 !heuristic_detections!) do (
	echo=- Task name: !heuristic_entry_taskname[%%A]! - "!heuristic_entry_filepath[%%A]!"
	for /F "delims=" %%# in ('%windir%\System32\schtasks.exe /query /tn "!heuristic_entry_taskname[%%A]!" /xml ^| %windir%\System32\findstr.exe /i "<Arguments>"') do (	
		set "line=%%#"
		set "line=!line:      <Arguments>=!"
		set "line=!line:</Arguments>=!"
		echo   - Full command: "!heuristic_entry_filepath[%%A]! !line:~0,-1!"
	)
)
echo=
echo=Invalid tasks ^(!invalid_entry!^) - these entries can be deleted as the file they are supposed to start does not exist:
for /l %%A in (1 1 !invalid_entry!) do (
	echo=- Task name: !invalid_entry_taskname[%%A]! "!invalid_entry_filepath[%%A]!"
)
echo=
echo=Pathless tasks ^(!pathless_entry!^) - these entries do not have a file to launch:
for /l %%A in (1 1 !pathless_entry!) do (
	echo=- Task name: !pathless_entry_taskname[%%A]! "!pathless_entry_filepath[%%A]!"
)
echo=
echo=Unknown entries ^(!unknown_path!^) - these entries could not be analyzed:
for /l %%A in (1 1 !unknown_path!) do (
	echo=- Task name: !unknown_entry_taskname[%%A]! - "!unknown_entry_filepath[%%A]!"
	for /F "delims=" %%# in ('%windir%\System32\schtasks.exe /query /tn "!unknown_entry_taskname[%%A]!" /xml ^| %windir%\System32\findstr.exe /i "<Arguments>"') do (	
		set "line=%%#"
		set "line=!line:      <Arguments>=!"
		set "line=!line:</Arguments>=!"
		echo   - Full command: "!unknown_entry_filepath[%%A]! !line:~0,-1!"
	)
)
echo=
echo=Submitted entries ^(!submitted!^) - these entries were submitted to analyze on VirusTotal:
for /l %%A in (1 1 !submitted!) do (
	echo=- Task name: !submitted_taskname[%%A]! - "!submitted_filepath[%%A]!"
	for /F "delims=" %%# in ('%windir%\System32\schtasks.exe /query /tn "!submitted_taskname[%%A]!" /xml ^| %windir%\System32\findstr.exe /i "<Arguments>"') do (	
		set "line=%%#"
		set "line=!line:      <Arguments>=!"
		set "line=!line:</Arguments>=!"
		echo   - Full command: "!submitted_filepath[%%A]! !line:~0,-1!"
	)
)
echo=
if "!submitted!" GTR "0" echo=We recommend re-scanning after several minutes to properly scan the yet unknown entries.
)>scheduled_tasks_scan[!log_number!].txt
echo=
echo=Scan has finished^^!
if exist "scheduled_tasks_scan[!log_number!].txt" (
	echo=Logfile was saved in %~dp0scheduled_tasks_scan[!log_number!].txt
) else (
	echo=Failed to save logfile.
)
echo=
pause
exit /b 0
