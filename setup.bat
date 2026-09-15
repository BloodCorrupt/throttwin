@echo off
setlocal enabledelayedexpansion
title Throttwin Setup

:: BatchGotAdmin
::-------------------------------------
REM  --> Check for permissions
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

REM --> If error flag set, we do not have admin.
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    set params = %*:"=""
    echo UAC.ShellExecute "cmd.exe", "/c %~s0 %params%", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    pushd "%CD%"
    CD /D "%~dp0"
::--------------------------------------

echo.
echo  =============================================
echo   Throttwin - Windows Bandwidth Limiter
echo   Setup Script
echo  =============================================
echo.

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python is not installed or not in PATH.
    echo  [ERROR] Please install Python 3.9+ from https://python.org
    pause
    exit /b 1
)

for /f "tokens=2" %%v in ('python --version 2^>^&1') do set PYVER=%%v
echo  [OK] Python %PYVER% found

:: Check Npcap
sc query npcap >nul 2>&1
if errorlevel 1 (
    sc query npf >nul 2>&1
    if errorlevel 1 (
        echo.
        echo  [WARNING] Npcap service not detected.
        echo  [WARNING] Throttwin requires Npcap to capture and inject packets.
        echo  [WARNING] Download from: https://npcap.com/#download
        echo.
        echo  Press any key to continue setup anyway ^(install Npcap separately^)...
        pause >nul
    ) else (
        echo  [OK] WinPcap/Npcap driver found
    )
) else (
    echo  [OK] Npcap service found
)

echo.
echo  Creating Virtual Environment...
echo  -----------------------------------------------
if not exist "venv" (
    python -m venv venv
    if errorlevel 1 (
        echo  [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
    echo  [OK] Virtual environment created in 'venv' folder
) else (
    echo  [OK] Virtual environment already exists
)

echo.
echo  Installing Python dependencies in venv...
echo  -----------------------------------------------

venv\Scripts\pip install -r requirements.txt
if errorlevel 1 (
    echo.
    echo  [ERROR] Dependency installation failed.
    pause
    exit /b 1
)

echo.
echo  =============================================
echo   Setup complete!
echo.
echo   To run Throttwin:
echo     run.bat           (CLI interactive mode)
echo     run.bat --web     (Web UI dashboard)
echo     run.bat --help    (Show all options)
echo.
echo   NOTE: Run as Administrator for full functionality.
echo  =============================================
echo.
pause
