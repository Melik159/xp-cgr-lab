@echo off
call "%~dp0set-j3-roots.bat"
if errorlevel 1 goto done
echo %DATE% %TIME% TRACE_FORMAT_BEGIN>>%DATAROOT%\timeline-guest.tsv
%TOOLROOT%\cgr_trace_runner.exe trace %DATAROOT%\J3LOG\format.stdout.txt %DATAROOT%\J3LOG\format.stderr.txt %DATAROOT%\J3LOG\format.metrics.json %DATAROOT%\J3LOG\format-cgr.jsonl %DATAROOT%\J3LOG\format-rtl.jsonl %DATAROOT%\J3LOG\format-hook.jsonl "%DATAROOT%\TC62A\TrueCrypt Format.exe"
echo %ERRORLEVEL%>%DATAROOT%\J3LOG\format.exit.txt
echo %DATE% %TIME% TRACE_FORMAT_END>>%DATAROOT%\timeline-guest.tsv
:done
