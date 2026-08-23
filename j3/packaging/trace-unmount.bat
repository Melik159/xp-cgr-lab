@echo off
call "%~dp0set-j3-roots.bat"
if errorlevel 1 goto done
echo %DATE% %TIME% TRACE_UNMOUNT_BEGIN>>%DATAROOT%\timeline-guest.tsv
%TOOLROOT%\cgr_trace_runner.exe trace %DATAROOT%\J3LOG\unmount.stdout.txt %DATAROOT%\J3LOG\unmount.stderr.txt %DATAROOT%\J3LOG\unmount.metrics.json %DATAROOT%\J3LOG\unmount-cgr.jsonl %DATAROOT%\J3LOG\unmount-rtl.jsonl %DATAROOT%\J3LOG\unmount-hook.jsonl "%DATAROOT%\TC62A\TrueCrypt.exe" /dismount T /quit /silent
echo %ERRORLEVEL%>%DATAROOT%\J3LOG\unmount.exit.txt
echo %DATE% %TIME% TRACE_UNMOUNT_END>>%DATAROOT%\timeline-guest.tsv
:done
