@echo off
set REPEATS=%1
if "%REPEATS%"=="" set REPEATS=5

echo Running CryptGenRandom probe (%REPEATS% repetitions)...
cgr_probe.exe --api cgr --repetitions %REPEATS% > cgr_probe.jsonl 2> cgr_probe.stderr.txt
set CGR_RC=%ERRORLEVEL%

echo Running SystemFunction036 probe separately (%REPEATS% repetitions)...
cgr_probe.exe --api rtl --repetitions %REPEATS% > rtl_probe.jsonl 2> rtl_probe.stderr.txt
set RTL_RC=%ERRORLEVEL%

echo CryptGenRandom exit code: %CGR_RC%
echo SystemFunction036 exit code: %RTL_RC%
echo Logs: cgr_probe.jsonl, cgr_probe.stderr.txt, rtl_probe.jsonl, rtl_probe.stderr.txt

if not "%CGR_RC%"=="0" exit /b %CGR_RC%
exit /b %RTL_RC%
