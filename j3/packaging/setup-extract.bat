@echo off
set DATAROOT=
for %%D in (C D E F G H I J K L M N O P Q R S T U V W X Y Z) do if exist %%D:\J3DATA.TAG set DATAROOT=%%D:
if "%DATAROOT%"=="" goto nodata
echo %DATE% %TIME% SETUP_EXTRACT_BEGIN>>%DATAROOT%\timeline-guest.tsv
start /wait "" "%~dp0TrueCrypt Setup 6.2a.exe"
echo %DATE% %TIME% SETUP_EXTRACT_END>>%DATAROOT%\timeline-guest.tsv
goto done
:nodata
echo J3DATA disk not found.
pause
:done
