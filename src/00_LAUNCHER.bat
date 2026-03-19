@echo off
:: =============================================================================
:: Windows Forensic Triage Toolkit -- Launcher
:: Version 1.0
:: 
:: Usage:
::   Double-click this file to run ALL modules in sequence
::   OR run individual modules from the modules\ folder directly
::
:: Requirements:
::   - Windows 10 / 11
::   - PowerShell 5.1 or later (built into all modern Windows)
::   - Run as Administrator for complete results
:: =============================================================================

title Windows Forensic Triage Toolkit

:: Check if running as Administrator
net session >nul 2>&1
if %errorLevel% NEQ 0 (
    echo.
    echo  ============================================================
    echo   WARNING: Not running as Administrator
    echo  ============================================================
    echo.
    echo   Some checks require Administrator privileges:
    echo     - BitLocker status
    echo     - Full event log access
    echo     - Service binary verification
    echo     - WMI subscription check
    echo.
    echo   For best results, right-click this file and choose
    echo   "Run as Administrator"
    echo.
    echo   Press any key to continue anyway with limited access...
    echo   Or close this window and re-run as Administrator.
    echo.
    pause
)

echo.
echo  ============================================================
echo   Windows Forensic Triage Toolkit v1.0
echo  ============================================================
echo.
echo   Host    : %COMPUTERNAME%
echo   User    : %USERNAME%
echo   Date    : %DATE% %TIME%
echo.
echo   Modules will run in sequence.
echo   Reports saved to: Reports\%COMPUTERNAME%_[timestamp]\
echo.
echo  ============================================================
echo.

:: Set PowerShell execution policy for this session only
:: This does NOT permanently change system policy
set PS_CMD=powershell.exe -NoProfile -ExecutionPolicy Bypass

:: Track results
set TOTAL_RED=0
set TOTAL_YELLOW=0

echo [1/9] Running Module 01 -- System Identity...
%PS_CMD% -File "%~dp0modules\01_SystemIdentity.ps1"
echo.

echo [2/9] Running Module 02 -- Storage ^& Files...
%PS_CMD% -File "%~dp0modules\02_StorageAndFiles.ps1"
echo.

echo [3/9] Running Module 03 -- Security Configuration...
%PS_CMD% -File "%~dp0modules\03_SecurityConfig.ps1"
echo.

echo [4/9] Running Module 04 -- Accounts ^& Authentication...
%PS_CMD% -File "%~dp0modules\04_AccountsAndAuth.ps1"
echo.

echo [5/9] Running Module 05 -- Processes ^& Software...
%PS_CMD% -File "%~dp0modules\05_ProcessesAndSoftware.ps1"
echo.

echo [6/9] Running Module 06 -- Persistence Mechanisms...
%PS_CMD% -File "%~dp0modules\06_Persistence.ps1"
echo.

echo [7/9] Running Module 07 -- Network Snapshot...
%PS_CMD% -File "%~dp0modules\07_NetworkSnapshot.ps1"
echo.

echo [8/9] Running Module 08 -- Network Time Series (5 min)...
%PS_CMD% -File "%~dp0modules\08_NetworkTimeSeries.ps1"
echo.

echo [9/9] Running Module 09 -- Forensic Artifacts...
%PS_CMD% -File "%~dp0modules\09_ForensicArtifacts.ps1"
echo.

echo.
echo  ============================================================
echo   All modules complete.
echo   Open the Reports\ folder to view HTML reports.
echo  ============================================================
echo.
pause
