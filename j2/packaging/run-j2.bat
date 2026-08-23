@echo off
set TOOLROOT=
for %%D in (D E F G H I J K L M N O P Q R S T U V W X Y Z) do if exist %%D:\cgr_trace_runner.exe set TOOLROOT=%%D
if "%TOOLROOT%"=="" goto no_tools

if not exist A:\RUN1 md A:\RUN1
if not exist A:\RUN2 md A:\RUN2

echo COMPUTERNAME=%COMPUTERNAME% > A:\environment.txt
ver >> A:\environment.txt
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v CSDVersion >> A:\environment.txt 2>&1
echo TOOLROOT=%TOOLROOT% >> A:\environment.txt

call :run_one RUN1
call :run_one RUN2
echo COMPLETE > A:\status.txt
goto done

:run_one
set RUN=%1

%TOOLROOT%:\cgr_trace_runner.exe control A:\%RUN%\control-cgr.jsonl A:\%RUN%\control-cgr.stderr.txt A:\%RUN%\control-cgr-metrics.json %TOOLROOT%:\cgr_probe.exe --api cgr --repetitions 5
echo %ERRORLEVEL% > A:\%RUN%\control-cgr.exit.txt

%TOOLROOT%:\cgr_trace_runner.exe trace A:\%RUN%\probe-cgr.jsonl A:\%RUN%\probe-cgr.stderr.txt A:\%RUN%\trace-cgr-metrics.json A:\%RUN%\cgr-trace.jsonl A:\%RUN%\unused-rtl.jsonl A:\%RUN%\cgr-hook-status.jsonl %TOOLROOT%:\cgr_probe.exe --api cgr --repetitions 5
echo %ERRORLEVEL% > A:\%RUN%\trace-cgr.exit.txt

%TOOLROOT%:\cgr_trace_runner.exe control A:\%RUN%\control-rtl.jsonl A:\%RUN%\control-rtl.stderr.txt A:\%RUN%\control-rtl-metrics.json %TOOLROOT%:\cgr_probe.exe --api rtl --repetitions 5
echo %ERRORLEVEL% > A:\%RUN%\control-rtl.exit.txt

%TOOLROOT%:\cgr_trace_runner.exe trace A:\%RUN%\probe-rtl.jsonl A:\%RUN%\probe-rtl.stderr.txt A:\%RUN%\trace-rtl-metrics.json A:\%RUN%\unused-cgr.jsonl A:\%RUN%\rtl-trace.jsonl A:\%RUN%\rtl-hook-status.jsonl %TOOLROOT%:\cgr_probe.exe --api rtl --repetitions 5
echo %ERRORLEVEL% > A:\%RUN%\trace-rtl.exit.txt
goto :eof

:no_tools
echo ERROR: J2 tools not found > A:\status.txt

:done
