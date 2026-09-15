@echo off
setlocal enabledelayedexpansion
title Throttwin

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

:: Check if venv exists
if not exist "venv\Scripts\python.exe" (
    echo.
    echo  [!] Virtual environment not found!
    echo  [!] Please run setup.bat first to install dependencies.
    echo.
    pause
    exit /b 1
)

:: ── Launch Throttwin ─────────────────────────────────────────
if "%1"=="--web" (
    venv\Scripts\python main.py --web %2 %3 %4
) else if "%1"=="-w" (
    venv\Scripts\python main.py --web %2 %3 %4
) else (
    venv\Scripts\python main.py %*
)

if errorlevel 1 (
    echo.
    echo  [!] Throttwin exited with an error.
    echo  [!] Make sure Npcap is installed and you are on a local network.
    pause
)
