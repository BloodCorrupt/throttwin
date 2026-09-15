@echo off
setlocal enabledelayedexpansion
title Throttwin Web UI (Localhost Only)

:: BatchGotAdmin
::-------------------------------------
REM  --> Check for permissions
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

REM --> If error flag set, we do not have admin.
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges for Throttwin Web UI (Localhost Only)...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    set "params=%*"
    echo UAC.ShellExecute "cmd.exe", "/c ""%~dp0runweb_localhost.bat"" %params%", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    pushd "%CD%"
    CD /D "%~dp0"
::--------------------------------------

:: Check if venv exists
if not exist "venv\Scripts\python.exe" (
    echo.
    echo  ==============================================================
    echo   [!] Virtual environment not found!
    echo   [!] Please run setup.bat first to install dependencies.
    echo  ==============================================================
    echo.
    pause
    exit /b 1
)

echo.
echo  ==============================================================
echo   THROTTWIN - Windows Bandwidth Limiter (Web UI - Localhost Only)
echo  ==============================================================
echo   Starting web dashboard bound strictly to 127.0.0.1...
echo   Open in browser: http://127.0.0.1:5000
echo   External LAN/Wi-Fi access is blocked.
echo   Press Ctrl+C in this terminal to stop the server.
echo  ==============================================================
echo.

venv\Scripts\python main.py --web --host 127.0.0.1 %*

if errorlevel 1 (
    echo.
    echo  [!] Throttwin Web UI exited with an error.
    echo  [!] Make sure Npcap is installed and you are on a local network.
    pause
)
