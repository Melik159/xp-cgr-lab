@echo off
call "%~dp0set-j3-roots.bat"
if errorlevel 1 goto done
echo COMPUTERNAME=%COMPUTERNAME%>%DATAROOT%\environment.txt
ver>>%DATAROOT%\environment.txt
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v CSDVersion>>%DATAROOT%\environment.txt 2>&1
echo TOOLROOT=%TOOLROOT%>>%DATAROOT%\environment.txt
echo DATAROOT=%DATAROOT%>>%DATAROOT%\environment.txt
dir "%DATAROOT%\TC62A">>%DATAROOT%\environment.txt
echo %DATE% %TIME% ENVIRONMENT_CAPTURED>>%DATAROOT%\timeline-guest.tsv
:done
