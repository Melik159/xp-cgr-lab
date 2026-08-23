@echo off
call "%~dp0set-j3-roots.bat"
if errorlevel 1 goto done
echo %DATE% %TIME% TRACE_FINAL_UNMOUNT_BEGIN>>%DATAROOT%\timeline-guest.tsv
%TOOLROOT%\cgr_trace_runner.exe trace %DATAROOT%\J3LOG\final-unmount.stdout.txt %DATAROOT%\J3LOG\final-unmount.stderr.txt %DATAROOT%\J3LOG\final-unmount.metrics.json %DATAROOT%\J3LOG\final-unmount-cgr.jsonl %DATAROOT%\J3LOG\final-unmount-rtl.jsonl %DATAROOT%\J3LOG\final-unmount-hook.jsonl "%DATAROOT%\TC62A\TrueCrypt.exe" /dismount T /quit /silent
echo %ERRORLEVEL%>%DATAROOT%\J3LOG\final-unmount.exit.txt
echo %DATE% %TIME% TRACE_FINAL_UNMOUNT_END>>%DATAROOT%\timeline-guest.tsv
:done
