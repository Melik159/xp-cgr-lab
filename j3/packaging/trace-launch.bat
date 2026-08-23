@echo off
call "%~dp0set-j3-roots.bat"
if errorlevel 1 goto done
echo %DATE% %TIME% TRACE_LAUNCH_BEGIN>>%DATAROOT%\timeline-guest.tsv
%TOOLROOT%\cgr_trace_runner.exe trace %DATAROOT%\J3LOG\launch.stdout.txt %DATAROOT%\J3LOG\launch.stderr.txt %DATAROOT%\J3LOG\launch.metrics.json %DATAROOT%\J3LOG\launch-cgr.jsonl %DATAROOT%\J3LOG\launch-rtl.jsonl %DATAROOT%\J3LOG\launch-hook.jsonl "%DATAROOT%\TC62A\TrueCrypt.exe"
echo %ERRORLEVEL%>%DATAROOT%\J3LOG\launch.exit.txt
echo %DATE% %TIME% TRACE_LAUNCH_END>>%DATAROOT%\timeline-guest.tsv
:done
