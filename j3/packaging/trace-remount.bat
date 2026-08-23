@echo off
call "%~dp0set-j3-roots.bat"
if errorlevel 1 goto done
echo %DATE% %TIME% TRACE_REMOUNT_BEGIN>>%DATAROOT%\timeline-guest.tsv
%TOOLROOT%\cgr_trace_runner.exe trace %DATAROOT%\J3LOG\remount.stdout.txt %DATAROOT%\J3LOG\remount.stderr.txt %DATAROOT%\J3LOG\remount.metrics.json %DATAROOT%\J3LOG\remount-cgr.jsonl %DATAROOT%\J3LOG\remount-rtl.jsonl %DATAROOT%\J3LOG\remount-hook.jsonl "%DATAROOT%\TC62A\TrueCrypt.exe" /volume "%DATAROOT%\j3micro.tc" /letter T /password J3micro62a /quit /silent
echo %ERRORLEVEL%>%DATAROOT%\J3LOG\remount.exit.txt
echo %DATE% %TIME% TRACE_REMOUNT_END>>%DATAROOT%\timeline-guest.tsv
:done
