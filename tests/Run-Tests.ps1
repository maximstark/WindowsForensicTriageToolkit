# =============================================================================
# Run-Tests.ps1 -- regression tests for the shared library and the built app
# =============================================================================
# Plain PowerShell 5.1, no Pester, so it runs the same on a fresh Windows box
# and on the CI runner.
#
#   .\tests\Run-Tests.ps1            library tests + app tests (needs build\TriageToolkit.exe)
#   .\tests\Run-Tests.ps1 -LibOnly   library tests only
#
# App tests launch the exe, whose manifest requires elevation: run them from
# an elevated prompt (GitHub's windows runners are).
# =============================================================================

param([switch]$LibOnly)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$script:Failed = 0
$script:Passed = 0

function Test([string]$Name, [scriptblock]$Body) {
    try {
        & $Body
        $script:Passed++
        Write-Host "  [PASS] $Name" -ForegroundColor Green
    } catch {
        $script:Failed++
        Write-Host "  [FAIL] $Name" -ForegroundColor Red
        Write-Host "         $($_.Exception.Message)" -ForegroundColor DarkRed
    }
}

function Assert([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("triage-tests-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Path $tmp | Out-Null

. (Join-Path $Root "src\lib\Common.ps1") | Out-Null

Write-Host ""
Write-Host "Common.ps1" -ForegroundColor Cyan

Test "finding text is HTML-encoded (report XSS)" {
    $f = New-Finding -Severity RED -Title "<script>alert(1)</script>" -Detail "Command: iex `"<img src=x onerror=alert(1)>`"" -WhyItMatters "a & b" -WhyMightBeNormal "<b>x</b>"
    $html = ConvertTo-HtmlFinding -Finding $f
    Assert ($html -notmatch "<script>") "raw <script> reached the HTML"
    Assert ($html -notmatch "<img ") "raw <img> reached the HTML"
    Assert ($html -match "&lt;script&gt;") "title was not encoded"
    Assert ($html -match "a &amp; b") "ampersand was not encoded"
}

Test "summary bar counts a single RED finding (PS 5.1 .Count on one object)" {
    $one = New-Finding -Severity RED -Title "t" -Detail "d" -WhyItMatters "w"
    $bar = Get-SummaryBar -AllFindings @($one)
    Assert ($bar -match "1 Critical") "expected '1 Critical' in: $bar"
    Assert ($bar -notmatch "All Clear") "a RED finding must not read 'All Clear'"
}

Test "module JSON gets a real file name and valid content" {
    $f = New-Finding -Severity YELLOW -Title "only one" -Detail "d" -WhyItMatters "w"
    Write-ModuleJson -ReportDir $tmp -ModuleNumber "07" -ModuleTitle "Network Snapshot" -Findings @($f) -Hostname "TESTHOST" -ScanTime "2026-01-01 00:00:00"
    $path = Join-Path $tmp "07_Network_Snapshot.json"
    Assert (Test-Path $path) "expected 07_Network_Snapshot.json (v1.5 wrote 07_.json)"
    $j = Get-Content $path -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert ($j.module -eq "07") "module field"
    Assert (@($j.findings).Count -eq 1) "one finding"
    Assert ($j.summary.yellow -eq 1) "summary.yellow"
}

Test "Winlogon: stock values are treated as safe" {
    Assert (Test-IsSafeWinlogonValue "C:\Windows\system32\userinit.exe,") "userinit with trailing comma"
    Assert (Test-IsSafeWinlogonValue "explorer.exe") "bare explorer.exe"
    Assert (Test-IsSafeWinlogonValue "%SystemRoot%\System32\sihost.exe") "env-var path"
}

Test "Winlogon: hijacks are NOT treated as safe" {
    Assert (-not (Test-IsSafeWinlogonValue "C:\Windows\system32\userinit.exe,C:\Users\Public\evil.exe")) "appended Userinit entry"
    Assert (-not (Test-IsSafeWinlogonValue "C:\Users\Public\explorer.exe")) "masquerading explorer.exe"
    Assert (-not (Test-IsSafeWinlogonValue "explorer.exe, C:\Temp\x.exe")) "appended Shell entry"
    Assert (-not (Test-IsSafeWinlogonValue "")) "empty value"
}

Test "toolkit's own workspace is whitelisted from the AppData scan" {
    Assert (Test-IsWhitelistedPath "C:\ProgramData\TriageToolkit-run-0123abcd\modules\01_SystemIdentity.ps1") "ProgramData workspace"
    Assert (-not (Test-IsWhitelistedPath "C:\ProgramData\SomethingElse\x.exe")) "other ProgramData paths stay in scope"
}

Test "developer environments are recognized; ordinary AppData folders are not" {
    Assert (Test-IsDevEnvironmentDir "C:\Users\a\AppData\Roaming\uv\tools\hf\Scripts") "uv tools"
    Assert (Test-IsDevEnvironmentDir "C:\Users\a\AppData\Local\Programs\x\Lib\site-packages\numpy.libs") "site-packages"
    Assert (Test-IsDevEnvironmentDir "C:\Users\a\AppData\Roaming\npm\node_modules\foo\bin") "node_modules"
    Assert (-not (Test-IsDevEnvironmentDir "C:\Users\a\AppData\Roaming\SyncHelper")) "plain AppData folder"
    Assert (-not (Test-IsDevEnvironmentDir "C:\Users\a\AppData\Local\Temp\x")) "Temp"
    Assert (-not (Test-IsDevEnvironmentDir "C:\Users\a\AppData\Roaming\inventory")) "'venv' must match a whole folder name"
}

Test "every script is pure ASCII (PS 5.1 reads BOM-less UTF-8 as ANSI)" {
    $files = @(Get-ChildItem (Join-Path $Root "src") -Recurse -Filter *.ps1)
    foreach ($f in $files) {
        $bad = @([IO.File]::ReadAllBytes($f.FullName) | Where-Object { $_ -gt 127 }).Count
        Assert ($bad -eq 0) "$($f.Name) has $bad non-ASCII bytes"
    }
}

Test "every module parses without syntax errors" {
    foreach ($f in Get-ChildItem (Join-Path $Root "src") -Recurse -Filter *.ps1) {
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$errors) | Out-Null
        Assert (@($errors).Count -eq 0) "$($f.Name): $($errors[0].Message)"
    }
}

if (-not $LibOnly) {
    Write-Host ""
    Write-Host "TriageToolkit.exe" -ForegroundColor Cyan
    $exe = Join-Path $Root "build\TriageToolkit.exe"

    Test "exe exists (run build.ps1 first)" { Assert (Test-Path $exe) "missing $exe" }

    if (Test-Path $exe) {
        Test "demo scan renders every page without crashing" {
            & (Join-Path $Root "tools\New-DemoScan.ps1") 6>$null | Out-Null
            $demo = Join-Path $Root "samples\DEMO-WS01"
            $scans = @(Get-ChildItem $demo -Directory | Sort-Object Name)
            $shots = Join-Path $tmp "shots"
            $p = Start-Process $exe -ArgumentList @("--render-docs", "`"$shots`"", "--scan", "`"$($scans[-1].FullName)`"", "--baseline", "`"$($scans[0].FullName)`"") -PassThru
            if (-not $p.WaitForExit(90000)) { $p.Kill(); throw "render timed out" }
            foreach ($n in "findings", "findings-new", "history", "export", "about", "scan-setup", "scan-running") {
                $png = Join-Path $shots "$n.png"
                Assert (Test-Path $png) "$n.png not rendered"
                Assert ((Get-Item $png).Length -gt 20000) "$n.png looks empty"
            }
        }

        Test "summary page and manifest are written and verify" {
            $scan = @(Get-ChildItem (Join-Path $Root "samples\DEMO-WS01") -Directory | Sort-Object Name)[-1].FullName
            $summary = Get-Content (Join-Path $scan "00_Summary.html") -Raw
            Assert ($summary -match "4 critical findings need attention") "verdict missing from 00_Summary.html"
            $m = Get-Content (Join-Path $scan "manifest.json") -Raw | ConvertFrom-Json
            Assert (@($m.files).Count -ge 20) "manifest lists too few files"
            foreach ($f in $m.files) {
                $h = (Get-FileHash (Join-Path $scan $f.file) -Algorithm SHA256).Hash
                Assert ($h -eq $f.sha256) "hash mismatch for $($f.file)"
            }
        }

        Test "--headless rejects an unknown module with exit code 3" {
            $p = Start-Process $exe -ArgumentList "--headless", "--modules", "42" -PassThru -Wait -WindowStyle Hidden
            Assert ($p.ExitCode -eq 3) "exit code was $($p.ExitCode)"
        }
    }
}

Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ""
$color = if ($script:Failed) { "Red" } else { "Green" }
Write-Host "$script:Passed passed, $script:Failed failed" -ForegroundColor $color
exit $script:Failed
