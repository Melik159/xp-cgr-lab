@echo off
set TOOLROOT=%~d0
set DATAROOT=
for %%D in (C D E F G H I J K L M N O P Q R S T U V W X Y Z) do if exist %%D:\J3DATA.TAG set DATAROOT=%%D:
if "%DATAROOT%"=="" goto error
if not exist %DATAROOT%\J3LOG md %DATAROOT%\J3LOG
exit /b 0
:error
echo J3DATA disk not found.
exit /b 1
