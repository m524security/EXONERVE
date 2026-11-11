@echo off
REM ============================================================
REM  Exonerve :: One-Click Launcher (Windows)
REM  Double-click this file, or run:  run.bat
REM  It installs deps if needed, starts the control plane,
REM  opens the dashboard, and fires a few attacks so you can
REM  watch the detection happen live.
REM ============================================================
cd /d "%~dp0"
title Exonerve Launcher

echo.
echo   ========================================
echo    EXONERVE  ::  starting up
echo   ========================================
echo.

REM --- make sure Python is available ---
python --version >nul 2>&1
IF ERRORLEVEL 1 (
    echo   [ERROR] Python not found. Install from https://python.org/downloads
    echo           and tick "Add Python to PATH" during setup.
    pause
    exit /b 1
)

REM --- install dependencies only if Flask is missing ---
python -c "import flask" >nul 2>&1
IF ERRORLEVEL 1 (
    echo   Installing dependencies ^(first run only^)...
    pip install -r requirements.txt
    IF ERRORLEVEL 1 (
        echo   [ERROR] Dependency install failed. Run:  pip install -r requirements.txt
        pause
        exit /b 1
    )
)

REM --- start the control plane in its OWN window ---
echo   Starting Control Plane ^(new window^)...
start "Exonerve Control Plane" cmd /k python host_control_plane\control_center.py

REM --- wait for it to come up, then open the dashboard ---
echo   Waiting for the control plane to come online...
timeout /t 5 /nobreak >nul
echo   Opening the SOC dashboard in your browser...
start "" http://127.0.0.1:5000

REM --- fire a few attacks so the dashboard fills with live data ---
timeout /t 2 /nobreak >nul
echo.
echo   Firing sample attacks so you can watch detection happen live:
echo.
echo    -^> ransomware
python fire_attack.py --attack ransomware
timeout /t 1 /nobreak >nul
echo    -^> credential dump
python fire_attack.py --attack cred_dump
timeout /t 1 /nobreak >nul
echo    -^> C2 beacon
python fire_attack.py --attack c2_beacon

echo.
echo   ========================================
echo    Dashboard is LIVE:  http://127.0.0.1:5000
echo   ========================================
echo.
echo   Fire more attacks any time with:
echo       python fire_attack.py --attack webshell
echo       python fire_attack.py --list        ^(see all attacks^)
echo.
echo   To STOP: close the "Exonerve Control Plane" window.
echo.
pause
