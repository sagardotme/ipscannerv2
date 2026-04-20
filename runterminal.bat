@echo off
setlocal
cd /d "%~dp0"
title IP Scanner Terminal
set "PYTHONDONTWRITEBYTECODE=1"

echo.
echo ========================================================================
echo  Terminal IP Scanner
echo ========================================================================
echo.

if not exist "ip.json" (
    echo [ERROR] ip.json was not found in:
    echo         %cd%
    echo.
    pause
    exit /b 1
)

if not exist "venv\Scripts\python.exe" (
    python --version >nul 2>&1
    if errorlevel 1 (
        echo [ERROR] Python is not installed or not available in PATH.
        echo         Install Python 3.8+ and run this file again.
        echo.
        pause
        exit /b 1
    )

    echo [*] Creating virtual environment...
    python -m venv venv
    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment.
        echo.
        pause
        exit /b 1
    )
)

set "PYTHON=venv\Scripts\python.exe"

echo [*] Checking terminal scanner dependencies...
"%PYTHON%" -c "import requests, psutil; from curl_cffi import requests as _" >nul 2>&1
if errorlevel 1 (
    echo [*] Installing missing dependencies...
    "%PYTHON%" -m pip install -q requests psutil curl-cffi
    if errorlevel 1 (
        echo [ERROR] Failed to install dependencies.
        echo.
        pause
        exit /b 1
    )
)

if not exist "found" (
    mkdir found
)

set "SCANNER_TERMINAL_WORKERS=4000"
set "SCANNER_TERMINAL_TIMEOUT=10"

echo [*] Starting terminal scan automatically...
echo.
"%PYTHON%" -B scanner_terminal.py
set "EXIT_CODE=%ERRORLEVEL%"

echo.
if not "%EXIT_CODE%"=="0" (
    echo [!] Scanner exited with code %EXIT_CODE%.
) else (
    echo [*] Scanner finished.
)
echo.
if /I not "%SCANNER_TERMINAL_NO_PAUSE%"=="1" pause
exit /b %EXIT_CODE%
