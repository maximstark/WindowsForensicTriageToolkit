# =============================================================================
# build.ps1 — Compile Windows Forensic Triage Toolkit into a single .exe
# =============================================================================
# Prerequisites: Windows 10/11 with .NET Framework 4.x (pre-installed)
# No additional software required — uses csc.exe from the .NET Framework
#
# Usage:
#   .\build.ps1
#   .\build.ps1 -OutputPath "C:\builds\TriageToolkit.exe"
#
# What this script does:
#   1. Locates csc.exe from the .NET Framework installation
#   2. Embeds all .ps1 module files and Common.ps1 as resources
#   3. Compiles TriageLauncher.cs into a Windows Forms executable
#   4. Embeds the UAC manifest for automatic elevation
#   5. Outputs TriageToolkit.exe to the build\ directory
#
# The resulting .exe can be distributed standalone — no dependencies needed.
# =============================================================================

param(
    [string]$OutputPath = ""
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host " Triage Toolkit Build Script" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# --- Step 1: Locate csc.exe ---
Write-Host "[1/5] Locating C# compiler..." -ForegroundColor Yellow

$cscPaths = @(
    # .NET Framework 4.8.x (most common on Win10/11)
    "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
    "$env:WINDIR\Microsoft.NET\Framework\v4.0.30319\csc.exe",
    # Fallback: search for any csc.exe
    (Get-ChildItem "$env:WINDIR\Microsoft.NET" -Filter "csc.exe" -Recurse -ErrorAction SilentlyContinue |
     Sort-Object FullName -Descending | Select-Object -First 1).FullName
)

$csc = $cscPaths | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1

if (-not $csc) {
    Write-Host "[FAIL] Could not find csc.exe. Ensure .NET Framework 4.x is installed." -ForegroundColor Red
    Write-Host "       On Windows 10/11 this should already be present." -ForegroundColor Red
    exit 1
}

Write-Host "  Found: $csc" -ForegroundColor Green

# --- Step 2: Verify source files exist ---
Write-Host "[2/5] Verifying source files..." -ForegroundColor Yellow

$srcDir      = Join-Path $ScriptDir "src"
$modulesDir  = Join-Path $srcDir "modules"
$libDir      = Join-Path $srcDir "lib"
$csFile      = Join-Path $srcDir "TriageLauncher.cs"
$manifestFile = Join-Path $srcDir "TriageLauncher.manifest"

$requiredFiles = @(
    $csFile,
    $manifestFile,
    (Join-Path $libDir "Common.ps1")
)

# Check all module files
$moduleFiles = @(
    "01_SystemIdentity.ps1",
    "02_StorageAndFiles.ps1",
    "03_SecurityConfig.ps1",
    "04_AccountsAndAuth.ps1",
    "05_ProcessesAndSoftware.ps1",
    "06_Persistence.ps1",
    "07_NetworkSnapshot.ps1",
    "08_NetworkTimeSeries.ps1",
    "09_ForensicArtifacts.ps1",
    "10_Correlation.ps1"
)

foreach ($mod in $moduleFiles) {
    $requiredFiles += Join-Path $modulesDir $mod
}

$missing = @()
foreach ($f in $requiredFiles) {
    if (-not (Test-Path $f)) {
        $missing += $f
        Write-Host "  [MISSING] $f" -ForegroundColor Red
    } else {
        Write-Host "  [OK] $(Split-Path -Leaf $f)" -ForegroundColor Green
    }
}

if ($missing.Count -gt 0) {
    Write-Host "`n[FAIL] $($missing.Count) required file(s) missing. Cannot build." -ForegroundColor Red
    exit 1
}

# --- Step 3: Prepare embedded resources ---
Write-Host "[3/5] Preparing embedded resources..." -ForegroundColor Yellow

$buildDir = Join-Path $ScriptDir "build"
if (-not (Test-Path $buildDir)) {
    New-Item -ItemType Directory -Path $buildDir -Force | Out-Null
}

$resourceDir = Join-Path $buildDir "resources"
if (Test-Path $resourceDir) { Remove-Item $resourceDir -Recurse -Force }
New-Item -ItemType Directory -Path $resourceDir -Force | Out-Null

# Copy all scripts to resource staging directory
Copy-Item (Join-Path $libDir "Common.ps1") (Join-Path $resourceDir "Common.ps1")
foreach ($mod in $moduleFiles) {
    Copy-Item (Join-Path $modulesDir $mod) (Join-Path $resourceDir $mod)
}

# Build the /resource arguments for csc.exe
$resourceArgs = @()
$resourceArgs += "/resource:`"$(Join-Path $resourceDir 'Common.ps1')`",TriageToolkit.scripts.Common.ps1"
foreach ($mod in $moduleFiles) {
    $resourceArgs += "/resource:`"$(Join-Path $resourceDir $mod)`",TriageToolkit.scripts.$mod"
}

Write-Host "  Prepared $($moduleFiles.Count + 1) embedded resources" -ForegroundColor Green

# --- Step 4: Compute SHA256 hashes for integrity verification ---
Write-Host "[4/5] Computing integrity hashes..." -ForegroundColor Yellow

$hashManifest = @{}
$allScripts = @((Join-Path $resourceDir "Common.ps1"))
$allScripts += $moduleFiles | ForEach-Object { Join-Path $resourceDir $_ }

foreach ($script in $allScripts) {
    $hash = (Get-FileHash -Path $script -Algorithm SHA256).Hash
    $name = Split-Path -Leaf $script
    $hashManifest[$name] = $hash
    Write-Host "  $name : $($hash.Substring(0,16))..." -ForegroundColor Gray
}

# Save hash manifest for distribution
$hashManifest | ConvertTo-Json | Out-File (Join-Path $buildDir "checksums.json") -Encoding UTF8
Write-Host "  Hash manifest saved to build\checksums.json" -ForegroundColor Green

# --- Step 5: Compile ---
Write-Host "[5/5] Compiling executable..." -ForegroundColor Yellow

if (-not $OutputPath) {
    $OutputPath = Join-Path $buildDir "TriageToolkit.exe"
}

# Build csc.exe command
$cscArgs = @(
    "/target:winexe",                           # Windows Forms app (no console window)
    "/platform:anycpu",                          # Run on x86 or x64
    "/optimize+",                                # Optimize output
    "/out:`"$OutputPath`"",                      # Output path
    "/win32manifest:`"$manifestFile`"",          # UAC elevation manifest
    "/reference:System.dll",                     # Core .NET
    "/reference:System.Drawing.dll",             # WinForms drawing
    "/reference:System.Windows.Forms.dll"        # WinForms UI
)

# Add resource arguments
$cscArgs += $resourceArgs

# Add source file
$cscArgs += "`"$csFile`""

$fullCmd = "& `"$csc`" $($cscArgs -join ' ')"
Write-Host "  Command: csc.exe [$(($cscArgs | Measure-Object).Count) arguments]" -ForegroundColor Gray

# Execute compilation
$process = Start-Process -FilePath $csc -ArgumentList $cscArgs -Wait -PassThru -NoNewWindow -RedirectStandardOutput (Join-Path $buildDir "build_stdout.log") -RedirectStandardError (Join-Path $buildDir "build_stderr.log")

if ($process.ExitCode -ne 0) {
    Write-Host ""
    Write-Host "[FAIL] Compilation failed with exit code $($process.ExitCode)" -ForegroundColor Red
    Write-Host ""
    Write-Host "--- Compiler Output ---" -ForegroundColor Yellow
    Get-Content (Join-Path $buildDir "build_stderr.log") -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Host "  $_" -ForegroundColor Red
    }
    Get-Content (Join-Path $buildDir "build_stdout.log") -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Host "  $_" -ForegroundColor Gray
    }
    exit 1
}

# Verify output exists
if (-not (Test-Path $OutputPath)) {
    Write-Host "[FAIL] Output file not created despite successful compilation." -ForegroundColor Red
    exit 1
}

$fileInfo = Get-Item $OutputPath
$fileHash = (Get-FileHash -Path $OutputPath -Algorithm SHA256).Hash

Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host " Build Successful" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Output:   $OutputPath"
Write-Host "  Size:     $([math]::Round($fileInfo.Length / 1KB, 1)) KB"
Write-Host "  SHA256:   $fileHash"
Write-Host "  Created:  $($fileInfo.CreationTime.ToString('yyyy-MM-dd HH:mm:ss'))"
Write-Host ""
Write-Host "  To distribute: copy TriageToolkit.exe to target machine and double-click."
Write-Host "  The UAC prompt will appear automatically."
Write-Host ""

# Cleanup resource staging
Remove-Item $resourceDir -Recurse -Force -ErrorAction SilentlyContinue

# Save build metadata
@{
    Version     = "1.5"
    BuildTime   = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    BuildHost   = $env:COMPUTERNAME
    Compiler    = $csc
    OutputHash  = $fileHash
    OutputSize  = $fileInfo.Length
    ScriptHashes = $hashManifest
} | ConvertTo-Json -Depth 3 | Out-File (Join-Path $buildDir "build_info.json") -Encoding UTF8
