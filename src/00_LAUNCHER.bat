@echo off
:: =============================================================================
:: Windows Forensic Triage Toolkit -- source launcher (v2.0)
::
:: Runs all ten modules from source in one report folder. Most people want
:: TriageToolkit.exe instead; this is for auditing or hacking on the scripts.
::
:: Usage: right-click > Run as administrator  (works without, with gaps)
:: Reports: src\Logs\<COMPUTERNAME>\<yyyy-MM-dd_HH-mm-ss>\
:: =============================================================================

setlocal
title Windows Forensic Triage Toolkit

net session >nul 2>&1
if %errorLevel% NEQ 0 (
    echo.
    echo   WARNING: not running as Administrator. BitLocker, the Security event
    echo   log, LSASS and all-user scheduled tasks will be missing or partial.
    echo   Close this window and use "Run as administrator" for a full scan,
    echo   or press any key to continue anyway.
    echo.
    pause
)

set PS_CMD=powershell.exe -NoProfile -ExecutionPolicy Bypass

:: One shared report folder for every module. Without this, each module would
:: start its own timestamped folder and module 10 would have nothing to join.
for /f "usebackq delims=" %%i in (`%PS_CMD% -Command "Get-Date -Format yyyy-MM-dd_HH-mm-ss"`) do set STAMP=%%i
set "TRIAGE_REPORT_DIR=%~dp0Logs\%COMPUTERNAME%\%STAMP%"
if not "%TRIAGE_NET_MINUTES%"=="" echo   Network watch: %TRIAGE_NET_MINUTES% min (TRIAGE_NET_MINUTES)

echo.
echo  ============================================================
echo   Windows Forensic Triage Toolkit -- %COMPUTERNAME%
echo   Reports: %TRIAGE_REPORT_DIR%
echo  ============================================================
echo.

for %%m in (01_SystemIdentity 02_StorageAndFiles 03_SecurityConfig 04_AccountsAndAuth 05_ProcessesAndSoftware 06_Persistence 07_NetworkSnapshot 08_NetworkTimeSeries 09_ForensicArtifacts 10_Correlation) do (
    echo --- %%m
    %PS_CMD% -File "%~dp0modules\%%m.ps1"
    echo.
)

echo  ============================================================
echo   All modules complete. Reports are in:
echo   %TRIAGE_REPORT_DIR%
echo  ============================================================
echo.
start "" explorer.exe "%TRIAGE_REPORT_DIR%"
pause
