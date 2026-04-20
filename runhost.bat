@echo off
chcp 65001 >nul
title Distributed Scanner Host
color 0B

REM Optional overrides for this host node:
REM set HOST_BIND=0.0.0.0
REM set HOST_PORT=8082
REM set HOST_DEFAULT_WORKERS=7000
REM set HOST_DEFAULT_TIMEOUT=15

if not defined HOST_PORT set HOST_PORT=8082
if not defined HOST_DEFAULT_WORKERS set HOST_DEFAULT_WORKERS=7000
if not defined HOST_DEFAULT_TIMEOUT set HOST_DEFAULT_TIMEOUT=15

echo.
echo ================================================================
echo   Distributed Scanner Host
echo ================================================================
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH.
    pause
    exit /b 1
)

if not exist "venv" (
    echo [*] Creating virtual environment...
    python -m venv venv
)

echo [*] Activating virtual environment...
call venv\Scripts\activate.bat

echo [*] Checking dependencies...
if /I "%SCANNER_FORCE_PIP_INSTALL%"=="1" (
    echo [*] Force-install requested, refreshing dependencies...
    pip install -q -r requirements.txt
) else (
    python -c "import fastapi, uvicorn, psutil, pydantic, curl_cffi" >nul 2>&1
    if errorlevel 1 (
        echo [*] Installing missing dependencies...
        pip install -q -r requirements.txt
    ) else (
        echo [*] Dependencies already installed - skipping pip install
    )
)

if not exist "found" (
    mkdir found
)

echo.
echo [*] Host UI will be available at: http://localhost:%HOST_PORT%
echo [*] If HOST_PORT is not set, host.py defaults to 8082.
echo.

python host.py

pause
