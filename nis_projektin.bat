@echo off
setlocal EnableExtensions
title Enterprise DDoS Shield

cd /d "%~dp0"
set "PROJECT_ROOT=%CD%"
set "PORT=8000"
set "BASE_URL=http://localhost:%PORT%/?ui=enterprise"
set "HEALTH_URL=http://127.0.0.1:%PORT%/api/health/live"
set "PYTHONPATH=%PROJECT_ROOT%"

echo ==================================================
echo      Enterprise DDoS Attack Detection System
echo ==================================================
echo.

net session >nul 2>&1
if not "%ERRORLEVEL%"=="0" (
    echo [+] Po hapet me privilegje Administrator...
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

set "PYTHON_EXE="
if exist "%PROJECT_ROOT%\.venv\Scripts\python.exe" set "PYTHON_EXE=%PROJECT_ROOT%\.venv\Scripts\python.exe"
if not defined PYTHON_EXE if exist "%PROJECT_ROOT%\venv\Scripts\python.exe" set "PYTHON_EXE=%PROJECT_ROOT%\venv\Scripts\python.exe"
if not defined PYTHON_EXE if exist "%PROJECT_ROOT%\..\.venv\Scripts\python.exe" set "PYTHON_EXE=%PROJECT_ROOT%\..\.venv\Scripts\python.exe"
if not defined PYTHON_EXE if exist "%PROJECT_ROOT%\..\venv\Scripts\python.exe" set "PYTHON_EXE=%PROJECT_ROOT%\..\venv\Scripts\python.exe"

if not defined PYTHON_EXE (
    for /f "delims=" %%P in ('where python.exe 2^>nul') do (
        if not defined PYTHON_EXE set "PYTHON_EXE=%%P"
    )
)

if not defined PYTHON_EXE (
    echo [!] Python nuk u gjet. Instalo Python ose krijo virtual environment.
    pause
    exit /b 1
)

if not exist "%PROJECT_ROOT%\.venv\Scripts\python.exe" (
    echo [+] Krijoj virtual environment lokal .venv...
    "%PYTHON_EXE%" -m venv "%PROJECT_ROOT%\.venv"
    if errorlevel 1 (
        echo [!] Krijimi i virtual environment deshtoi.
        pause
        exit /b 1
    )
)
set "PYTHON_EXE=%PROJECT_ROOT%\.venv\Scripts\python.exe"

echo [+] Python: %PYTHON_EXE%
echo [+] Dashboard: %BASE_URL%
echo.

if not exist ".env" if exist ".env.example" (
    copy /Y ".env.example" ".env" >nul
    echo [+] U krijua .env nga .env.example
)

echo [+] Kontrolloj nese serveri eshte tashme online...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "try { $r = Invoke-WebRequest -UseBasicParsing -Uri '%HEALTH_URL%' -TimeoutSec 2; if ($r.StatusCode -eq 200) { exit 0 } } catch {}; exit 1"
if not errorlevel 1 echo [+] Serveri ekzistues do te riniset per te aplikuar konfigurimin fail-safe.

echo [+] Pastroj procese te vjetra te serverit nese ekzistojne...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Get-CimInstance Win32_Process | Where-Object { (($_.Name -eq 'python.exe' -or $_.Name -eq 'pythonw.exe') -and $_.CommandLine -like '*src.api.server*') -or ($_.Name -eq 'tshark.exe' -and $_.CommandLine -like '*-T fields*') } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }"

echo [+] Kontrolloj librarite Python...
"%PYTHON_EXE%" -m pip install -r requirements.txt --quiet
if errorlevel 1 (
    echo [!] Instalimi i librarive deshtoi. Kontrollo internetin dhe requirements.txt.
    pause
    exit /b 1
)

echo [+] Po nis serverin ne sfond...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%PYTHON_EXE%' -ArgumentList '-m','src.api.server' -WorkingDirectory '%PROJECT_ROOT%' -WindowStyle Hidden"

echo [+] Po pres derisa API te jete gati...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$deadline = (Get-Date).AddSeconds(120); while ((Get-Date) -lt $deadline) { try { $r = Invoke-WebRequest -UseBasicParsing -Uri '%HEALTH_URL%' -TimeoutSec 2; if ($r.StatusCode -eq 200) { exit 0 } } catch {}; Start-Sleep -Milliseconds 700 }; exit 1"
if errorlevel 1 (
    echo [!] Serveri nuk u be gati pas 2 minutash.
    echo [!] Provo manualisht: %BASE_URL%
    pause
    exit /b 1
)

:ready
echo.
echo [+] SERVERI ESHTE ONLINE.
echo [+] Po hap dashboard-in: %BASE_URL%
set "BROWSER_EXE="
if exist "%ProgramFiles%\Google\Chrome\Application\chrome.exe" set "BROWSER_EXE=%ProgramFiles%\Google\Chrome\Application\chrome.exe"
if not defined BROWSER_EXE if exist "%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe" set "BROWSER_EXE=%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"
if not defined BROWSER_EXE if exist "%ProgramFiles%\Microsoft\Edge\Application\msedge.exe" set "BROWSER_EXE=%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"
if not defined BROWSER_EXE if exist "%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe" set "BROWSER_EXE=%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"

if defined BROWSER_EXE (
    start "" "%BROWSER_EXE%" --new-window "%BASE_URL%"
) else (
    start "" "%BASE_URL%"
)
echo.
echo Mund ta mbyllesh kete dritare. Serveri vazhdon ne sfond.
pause
