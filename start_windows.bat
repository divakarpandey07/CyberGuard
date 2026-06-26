@echo off
title CyberGuard IDS v4
chcp 65001 >nul 2>&1

:: Check for Administrator privileges
net session >nul 2>&1
if '%errorlevel%' == '0' (
    goto gotAdmin
)

:: If already attempted elevation once, do not loop
if "%~1" == "--elevated" (
    echo.
    echo  [ERROR] Elevation failed or was denied.
    echo  Please open Command Prompt as Administrator manually:
    echo  Right-click CMD -> Run as Administrator
    echo.
    pause
    exit /B 1
)

echo.
echo  ===================================================
echo   [!] Requesting Administrative Privileges...
echo   This is required for live packet capture to work.
echo  ===================================================
echo.

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "cmd.exe", "/c """%~s0""" --elevated", "", "runas", 1 >> "%temp%\getadmin.vbs"
    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    cd /d "%~dp0"

echo.
echo  ===================================================
echo   🛡️  CyberGuard IDS v4 - Starting...
echo  ===================================================
echo.

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python not found!
    echo  Download from: https://python.org/downloads
    echo  Make sure to check "Add Python to PATH" during install!
    pause & exit /b 1
)

:: Create venv if needed
if not exist "venv" (
    echo  [*] Creating virtual environment...
    python -m venv venv
    if errorlevel 1 (
        echo  [ERROR] Failed to create virtual environment
        pause & exit /b 1
    )
)

:: Activate venv
call venv\Scripts\activate.bat

:: Install deps
echo  [*] Installing/checking dependencies...
pip install -r requirements.txt -q --disable-pip-version-check

:: .env reminder
if not exist ".env" (
    echo.
    echo  [!] No .env file found.
    echo  [!] Run setup wizard for Telegram/Email alerts:
    echo      python backend\setup_wizard.py
    echo  [!] Or copy: copy .env.example .env
    echo.
)

:: Check models
if not exist "backend\models\xgb_model.pkl" (
    echo.
    echo  ================================================================
    echo   WARNING: ML Models not found
    echo  ================================================================
    echo   Train models now to enable detection:
    echo     python backend\train.py --fast
    echo  ================================================================
    echo.
    set /p choice="Train with fast mode now? (y/n): "
    if /i "%choice%"=="y" (
        python backend\train.py --fast
    )
)

echo.
echo  ===================================================
echo   Dashboard: http://localhost:5000
echo   Live capture: ENABLED (Running as Administrator)
echo   Press Ctrl+C to stop
echo  ===================================================
echo.

:: Run from project root
python backend\app.py
pause
