@echo off
call "%~dp0set-j3-roots.bat"
if errorlevel 1 goto done
echo %DATE% %TIME% TRACE_MOUNT_BEGIN>>%DATAROOT%\timeline-guest.tsv
%TOOLROOT%\cgr_trace_runner.exe trace %DATAROOT%\J3LOG\mount.stdout.txt %DATAROOT%\J3LOG\mount.stderr.txt %DATAROOT%\J3LOG\mount.metrics.json %DATAROOT%\J3LOG\mount-cgr.jsonl %DATAROOT%\J3LOG\mount-rtl.jsonl %DATAROOT%\J3LOG\mount-hook.jsonl "%DATAROOT%\TC62A\TrueCrypt.exe" /volume "%DATAROOT%\j3micro.tc" /letter T /password J3micro62a /quit /silent
echo %ERRORLEVEL%>%DATAROOT%\J3LOG\mount.exit.txt
echo %DATE% %TIME% TRACE_MOUNT_END>>%DATAROOT%\timeline-guest.tsv
:done
