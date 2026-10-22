@echo off
REM ============================================================
REM  ProtectRequest - presentation demo
REM  Double-click, or run:  demo.bat        (pauses between steps)
REM                         demo.bat auto   (no pauses)
REM  Force a Python:        set PROTECT_PY=C:\path\to\python.exe
REM ============================================================
setlocal
cd /d "%~dp0"
chcp 65001 >nul
title ProtectRequest Demo

if /i "%~1"=="auto" set AUTO=1

REM ---- find a WORKING Python ---------------------------------------
REM Each candidate must run real code (not just --version), which skips
REM broken installs and the Microsoft Store stub. First one that works wins.
set PY=
if defined PROTECT_PY call :trypath "%PROTECT_PY%"
call :trycmd python
call :trycmd "py -3"
for %%V in (3.13 3.12 3.11 3.10 3.9) do call :trycmd "py -%%V"
for /d %%D in ("%LOCALAPPDATA%\Programs\Python\Python3*") do call :trypath "%%D\python.exe"
for /d %%D in ("%ProgramFiles%\Python3*") do call :trypath "%%D\python.exe"
for /d %%D in ("P:\Programs\Python*") do call :trypath "%%D\python.exe"
for /d %%D in ("C:\Python3*") do call :trypath "%%D\python.exe"
if not defined PY goto nopython
echo Using Python: %PY%

set OUT=demo_output
if not exist "%OUT%" mkdir "%OUT%"

REM ---- step 0: setup ----------------------------------------------
call :header "0/9  Setup: installing dependencies"
echo Python: %PY%
%PY% -m pip install -q -r requirements.txt pytest
%PY% run.py --version
call :next

REM ---- step 1: what it supports -----------------------------------
call :header "1/9  Supported log formats and detection rules"
%PY% run.py formats
echo.
%PY% run.py rules
call :next

REM ---- step 2: tests ----------------------------------------------
call :header "2/9  Running the test suite"
%PY% -m pytest -q -p no:cacheprovider
call :next

REM ---- step 3: web log -> HTML report -----------------------------
call :header "3/9  Analysing an Apache/Nginx access log"
%PY% run.py analyze samples\web_access.log --no-abuse -o "%OUT%\web_report.html"
echo.
echo Opening the HTML report in your browser...
start "" "%OUT%\web_report.html"
call :next

REM ---- step 4: SSH brute force ------------------------------------
call :header "4/9  Analysing an SSH auth.log (brute force + compromise)"
%PY% run.py analyze samples\auth.log --no-abuse --no-html
call :next

REM ---- step 5: every format at once + exports ---------------------
call :header "5/9  All 5 formats at once, with JSON + CSV export"
%PY% run.py analyze samples\ --no-abuse -q -o "%OUT%\full_report.html" --json "%OUT%\report.json" --csv "%OUT%\report.csv"
echo.
echo Files written to %OUT%\ :
dir /b "%OUT%"
call :next

REM ---- step 6: report is XSS-safe ---------------------------------
call :header "6/9  Security check: XSS payload inside a log"
%PY% tools\demo_feed.py xss "%OUT%\xss.log"
echo The log contains a ^<script^> tag. In v1 it would run in the report.
echo.
%PY% run.py analyze "%OUT%\xss.log" --no-abuse -q -o "%OUT%\xss_report.html"
echo.
echo Opening the report: the payload must show as TEXT, with NO popup.
start "" "%OUT%\xss_report.html"
call :next

REM ---- step 7: live watch mode ------------------------------------
call :header "7/9  LIVE: watch mode with real-time alerts"
%PY% tools\demo_feed.py init "%OUT%\live.log"
if exist "%OUT%\alerts.jsonl" del "%OUT%\alerts.jsonl"
REM Launcher file: avoids cmd's quote-stripping when the Python path has spaces.
> "%OUT%\watch.cmd" echo @cd /d "%CD%"
>> "%OUT%\watch.cmd" echo @%PY% run.py watch "%OUT%\live.log" --no-abuse --interval 0.5 --alert-file "%OUT%\alerts.jsonl" --report "%OUT%\live_report.html"
echo Opening the watch window...
start "ProtectRequest LIVE" cmd /k "%OUT%\watch.cmd"
timeout /t 4 /nobreak >nul
echo.
echo Sending attacks to the live log (watch the other window):
%PY% tools\demo_feed.py attack "%OUT%\live.log"
echo.
echo In the watch window press Ctrl+C to stop; it writes live_report.html.
call :next

REM ---- step 8: CI / cron exit code --------------------------------
call :header "8/9  Automation: fail the job if high-risk IPs are found"
%PY% run.py analyze samples\web_access.log --no-abuse -q --no-html --fail-on high
echo Exit code: %ERRORLEVEL%   (2 = high-risk IPs found, 0 = clean)
call :next

REM ---- step 9: IP lookup ------------------------------------------
call :header "9/9  Threat intel: IP lookup (GeoIP, + AbuseIPDB if key set)"
%PY% run.py check-ip 8.8.8.8 1.1.1.1 203.0.113.66
echo.
echo ============================================================
echo   Demo complete. Outputs are in %OUT%\
echo ============================================================
pause
endlocal
exit /b 0


REM ---- helpers ----------------------------------------------------
:trycmd
REM %~1 = a command, e.g.  python   or   py -3.10
if defined PY exit /b 0
%~1 -c "import encodings, os, json, ssl" >nul 2>&1 && set "PY=%~1"
exit /b 0

:trypath
REM %~1 = full path to a python.exe (may contain spaces)
if defined PY exit /b 0
if not exist "%~1" exit /b 0
"%~1" -c "import encodings, os, json, ssl" >nul 2>&1 && set PY="%~1"
exit /b 0

:header
cls
echo ============================================================
echo   %~1
echo ============================================================
echo.
exit /b 0

:next
echo.
if defined AUTO exit /b 0
echo ------------------------------------------------------------
pause
exit /b 0

:nopython
echo.
echo  No working Python 3 found.
echo  Checked: PATH, py launcher, AppData, Program Files, P:\Programs, C:\Python3*
echo  Fix: Settings - Apps - Python 3.x - Modify - Repair,
echo  or set PROTECT_PY to a working python.exe and run again.
echo.
pause
exit /b 1
