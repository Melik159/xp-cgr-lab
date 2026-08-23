@echo off
set PROBE=
for %%D in (D E F G H I J K L M N O P Q R S T U V W X Y Z) do if exist %%D:\cgr_probe.exe set PROBE=%%D:\cgr_probe.exe
if "%PROBE%"=="" goto no_probe

echo COMPUTERNAME=%COMPUTERNAME% > A:\xp-environment.txt
ver >> A:\xp-environment.txt
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v CSDVersion >> A:\xp-environment.txt 2>&1
echo PROBE=%PROBE% >> A:\xp-environment.txt

%PROBE% --api cgr --repetitions 5 > A:\cgr-xp.jsonl 2> A:\cgr-xp.stderr.txt
echo %ERRORLEVEL% > A:\cgr-xp.exit.txt

%PROBE% --api rtl --repetitions 5 > A:\rtl-xp.jsonl 2> A:\rtl-xp.stderr.txt
echo %ERRORLEVEL% > A:\rtl-xp.exit.txt

echo COMPLETE > A:\status.txt
goto done

:no_probe
echo ERROR: cgr_probe.exe not found on CD drives > A:\status.txt

:done
