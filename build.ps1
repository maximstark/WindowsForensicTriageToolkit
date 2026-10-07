# =============================================================================
# build.ps1 -- compile Windows Forensic Triage Toolkit into a single .exe
# =============================================================================
# Prerequisites: Windows 10/11. Nothing to install -- uses the csc.exe and WPF
# assemblies that ship with the in-box .NET Framework 4.8.
#
# Usage:
#   .\build.ps1
#   .\build.ps1 -OutputPath "C:\builds\TriageToolkit.exe"
#
# What it does:
#   1. Pre-flight: PowerShell scripts must be pure ASCII (PS 5.1 reads BOM-less
#      UTF-8 as ANSI and mangles anything else); XAML must be well-formed
#   2. Stages the 11 scripts, the XAML views and the icon as embedded resources
#   3. Hashes every script (SHA-256) into checksums.json AND into generated
#      BuildInfo.g.cs, so the exe can verify its scripts before running them
#   4. Compiles src\app\*.cs into a WPF app with the UAC manifest and icon
# =============================================================================

param(
    [string]$OutputPath = ""
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path

function Step($n, $text) { Write-Host "[$n/5] $text" -ForegroundColor Yellow }
function Fail($text) { Write-Host "`n[FAIL] $text" -ForegroundColor Red; exit 1 }

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host " Triage Toolkit Build" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

$src       = Join-Path $Root "src"
$appDir    = Join-Path $src "app"
$uiDir     = Join-Path $src "ui"
$libDir    = Join-Path $src "lib"
$modDir    = Join-Path $src "modules"
$buildDir  = Join-Path $Root "build"
$objDir    = Join-Path $buildDir "obj"
$manifest  = Join-Path $src "TriageToolkit.manifest"
$icon      = Join-Path $uiDir "app.ico"

# --- 1. Compiler + pre-flight -------------------------------------------------
Step 1 "Locating compiler and checking sources..."
$fw  = Join-Path $env:WINDIR "Microsoft.NET\Framework64\v4.0.30319"
if (-not (Test-Path (Join-Path $fw "csc.exe"))) { $fw = Join-Path $env:WINDIR "Microsoft.NET\Framework\v4.0.30319" }
$csc = Join-Path $fw "csc.exe"
$wpf = Join-Path $fw "WPF"
if (-not (Test-Path $csc)) { Fail "csc.exe not found. .NET Framework 4.x should be present on every Windows 10/11 machine." }
if (-not (Test-Path (Join-Path $wpf "PresentationFramework.dll"))) { Fail "WPF assemblies not found under $wpf" }
Write-Host "  Compiler: $csc" -ForegroundColor Gray

$scripts = @(Join-Path $libDir "Common.ps1") + @(
    "01_SystemIdentity.ps1", "02_StorageAndFiles.ps1", "03_SecurityConfig.ps1",
    "04_AccountsAndAuth.ps1", "05_ProcessesAndSoftware.ps1", "06_Persistence.ps1",
    "07_NetworkSnapshot.ps1", "08_NetworkTimeSeries.ps1", "09_ForensicArtifacts.ps1",
    "10_Correlation.ps1" | ForEach-Object { Join-Path $modDir $_ })
$csFiles = @(Get-ChildItem $appDir -Filter *.cs | Sort-Object Name)
$xaml    = @(Get-ChildItem $uiDir -Filter *.xaml | Sort-Object Name)

$problems = @()
foreach ($f in $scripts + @($manifest, $icon)) { if (-not (Test-Path $f)) { $problems += "missing: $f" } }
foreach ($f in $scripts | Where-Object { Test-Path $_ }) {
    $bytes = [IO.File]::ReadAllBytes($f)
    $bad = 0; foreach ($b in $bytes) { if ($b -gt 127) { $bad++ } }
    if ($bad) { $problems += "non-ASCII bytes ($bad) in $(Split-Path -Leaf $f) -- PS 5.1 would mis-decode them" }
}
foreach ($x in $xaml) {
    try { [xml](Get-Content $x.FullName -Raw -Encoding UTF8) | Out-Null } catch { $problems += "malformed XAML $($x.Name): $($_.Exception.Message)" }
}
if ($csFiles.Count -eq 0) { $problems += "no C# sources in $appDir" }
if ($problems) { $problems | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }; Fail "$($problems.Count) pre-flight problem(s)." }
Write-Host "  $($scripts.Count) scripts (ASCII), $($xaml.Count) XAML views, $($csFiles.Count) C# files: OK" -ForegroundColor Green

# --- 2. Version ----------------------------------------------------------------
Step 2 "Reading version..."
$verLine = Select-String -Path (Join-Path $libDir "Common.ps1") -Pattern '^\$TOOLKIT_VERSION\s*=\s*"([\d.]+)"' | Select-Object -First 1
if (-not $verLine) { Fail "Could not read `$TOOLKIT_VERSION from Common.ps1" }
$version = $verLine.Matches[0].Groups[1].Value
$parts = @($version.Split('.')); while ($parts.Count -lt 4) { $parts += "0" }
$asmVersion = ($parts[0..3] -join '.')
$commit = ""
try { $commit = (& git -C $Root rev-parse --short HEAD 2>$null) } catch { }
Write-Host "  Version $version ($asmVersion)$(if ($commit) { ", commit $commit" })" -ForegroundColor Green

# --- 3. Stage resources + hashes ---------------------------------------------
Step 3 "Staging embedded resources and hashing scripts..."
if (Test-Path $objDir) { Remove-Item $objDir -Recurse -Force }
New-Item -ItemType Directory -Path $objDir -Force | Out-Null

$resArgs = @()
$hashes  = [ordered]@{}
foreach ($f in $scripts) {
    $name = Split-Path -Leaf $f
    $hashes[$name] = (Get-FileHash -Path $f -Algorithm SHA256).Hash
    $resArgs += "/resource:`"$f`",TriageToolkit.scripts.$name"
}
foreach ($x in $xaml) { $resArgs += "/resource:`"$($x.FullName)`",TriageToolkit.ui.$($x.Name)" }
$resArgs += "/resource:`"$icon`",TriageToolkit.ui.app.ico"

$hashLines = ($hashes.GetEnumerator() | ForEach-Object { "            { `"$($_.Key)`", `"$($_.Value)`" }," }) -join "`r`n"
$buildDate = Get-Date -Format "yyyy-MM-dd"
$gen = @"
// <auto-generated> by build.ps1 -- do not edit </auto-generated>
using System.Collections.Generic;
namespace TriageToolkit
{
    static class BuildInfo
    {
        public const string Version = "$version";
        public const string AssemblyVersion = "$asmVersion";
        public const string BuildDate = "$buildDate";
        public const string Commit = "$commit";
        public static readonly Dictionary<string, string> ScriptHashes = new Dictionary<string, string>
        {
$hashLines
        };
    }
}
"@
$genFile = Join-Path $objDir "BuildInfo.g.cs"
[IO.File]::WriteAllText($genFile, $gen, (New-Object Text.UTF8Encoding $false))

# Plain-text pretty JSON (ConvertTo-Json on PS 5.1 indents oddly, but it is valid)
$hashes | ConvertTo-Json | Out-File (Join-Path $buildDir "checksums.json") -Encoding UTF8
foreach ($k in $hashes.Keys) { Write-Host ("  {0,-30} {1}..." -f $k, $hashes[$k].Substring(0, 16)) -ForegroundColor Gray }

# --- 4. Compile ----------------------------------------------------------------
Step 4 "Compiling..."
if (-not $OutputPath) { $OutputPath = Join-Path $buildDir "TriageToolkit.exe" }
$refs = "System.dll", "System.Core.dll", "System.Xml.dll", "System.Xaml.dll", "System.Web.Extensions.dll",
        "WindowsBase.dll", "PresentationCore.dll", "PresentationFramework.dll"
$cscArgs = @(
    "/nologo", "/target:winexe", "/platform:anycpu", "/optimize+", "/codepage:65001", "/warn:4",
    "/out:`"$OutputPath`"",
    "/win32manifest:`"$manifest`"",
    "/win32icon:`"$icon`"",
    "/lib:`"$wpf`""
) + ($refs | ForEach-Object { "/reference:$_" }) + $resArgs + ("`"$genFile`"") + ($csFiles | ForEach-Object { "`"$($_.FullName)`"" })

$rsp = Join-Path $objDir "csc.rsp"
[IO.File]::WriteAllLines($rsp, [string[]]$cscArgs)
$output = & $csc "@$rsp" 2>&1
$code = $LASTEXITCODE
$output | Out-File (Join-Path $buildDir "build.log") -Encoding UTF8
$output | Where-Object { $_ -match "warning|error" } | ForEach-Object {
    $color = if ($_ -match "error") { "Red" } else { "DarkYellow" }
    Write-Host "  $_" -ForegroundColor $color
}
if ($code -ne 0) { Fail "Compilation failed (exit $code). Full output: build\build.log" }

# --- 5. Metadata -----------------------------------------------------------------
Step 5 "Writing build metadata..."
$fileInfo = Get-Item $OutputPath
$fileHash = (Get-FileHash -Path $OutputPath -Algorithm SHA256).Hash
[ordered]@{
    Version      = $version
    Commit       = $commit
    BuildTime    = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    Compiler     = $csc
    OutputSize   = $fileInfo.Length
    OutputHash   = $fileHash
    ScriptHashes = $hashes
} | ConvertTo-Json -Depth 3 | Out-File (Join-Path $buildDir "build_info.json") -Encoding UTF8

Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host " Build successful" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host "  Output:  $OutputPath"
Write-Host "  Size:    $([math]::Round($fileInfo.Length / 1KB, 1)) KB"
Write-Host "  SHA256:  $fileHash"
Write-Host ""
