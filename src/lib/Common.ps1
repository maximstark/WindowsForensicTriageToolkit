# =============================================================================
# Common.ps1 -- Shared Library for Windows Forensic Triage Toolkit
# Version: 1.5
# Compatible: Windows 10/11, PowerShell 5.1+
# =============================================================================

# Encoding fix -- ensures correct display on all Windows code pages
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

# --- CONSTANTS ----------------------------------------------------------------

$TOOLKIT_VERSION = "1.5"

$SEV_GREEN  = "GREEN"
$SEV_YELLOW = "YELLOW"
$SEV_RED    = "RED"
$SEV_INFO   = "INFO"

$KNOWN_GOOD_PUBLISHERS = @(
    "Microsoft", "Microsoft Corporation", "Microsoft Windows",
    "HP Inc", "Hewlett-Packard", "HP",
    "Advanced Micro Devices", "AMD",
    "Intel Corporation", "Intel",
    "Realtek Semiconductor", "Realtek",
    "MEDIATEK", "MediaTek",
    "Synaptics", "DTS Inc", "Sunplus Innovation",
    "Google LLC", "Apple Inc", "Adobe",
    "NVIDIA Corporation", "Qualcomm",
    "Dell", "Lenovo", "ASUS", "Acer",
    "Logitech", "Corsair", "SteelSeries"
)

$KNOWN_RAT_NAMES = @(
    "anydesk", "teamviewer", "ammyy", "supremo", "remotepc",
    "logmein", "gotomypc", "dameware", "vnc", "tightvnc",
    "realvnc", "ultravnc", "tigervnc", "dwagent", "dwservice",
    "screenconnect", "connectwise", "splashtop", "showmypc",
    "radmin", "netop", "pcanywhere", "netsupport",
    "darkcomet", "njrat", "quasar", "nanocore", "asyncrat",
    "remcos", "xworm", "warzone", "agent tesla",
    "cobaltstrike", "beacon", "meterpreter",
    "psexec", "mimikatz", "lazagne",
    "netcat", "ncat", "socat"
)

# v1.5: Executable extensions only -- web assets (.js, .css, .html, .svg, .png)
# are NOT executables and cannot be code-signed, producing mass false positives
$EXECUTABLE_EXTENSIONS = @(
    "*.exe", "*.dll", "*.ps1", "*.vbs", "*.bat", "*.cmd",
    "*.hta", "*.scr", "*.pif", "*.com", "*.wsf", "*.wsh"
)

# v1.5: Known Microsoft/browser AppData paths with legitimate unsigned files
$WHITELISTED_APPDATA_PATHS = @(
    "*\Microsoft\OneDrive\*",
    "*\Microsoft\Edge\*",
    "*\Microsoft\Teams\*",
    "*\Microsoft\Windows\*\Edge*",
    "*\Google\Chrome\*",
    "*\Mozilla\Firefox\*",
    "*\Microsoft\WindowsApps\*",
    "*\chocolatey\*",
    "*\AppData\Roaming\npm\*",
    "*\AppData\Roaming\uv\*"
)

$SUSPICIOUS_PATHS = @(
    "$env:APPDATA",
    "$env:LOCALAPPDATA\Temp",
    "$env:TEMP",
    "C:\Windows\Temp",
    "C:\ProgramData",
    "$env:PUBLIC",
    "C:\Users\Public"
)

$SUSPICIOUS_PORTS = @(
    1337, 4444, 4445, 5555, 6666, 7777, 8888, 9999,
    1080, 3389, 5900, 5901, 22, 23,
    8080, 8443, 9090
)

# v1.5: Known process name to vendor mapping for noise reduction in network findings
$ProcessVendorMap = @{
    "firefox"           = "Mozilla"
    "steam"             = "Valve"
    "steamwebhelper"    = "Valve"
    "Plex Media Server" = "Plex Inc"
    "ProtonVPN.Client"  = "Proton AG"
    "ProtonVPNService"  = "Proton AG"
    "ProtonDrive"       = "Proton AG"
    "APSDaemon"         = "Apple"
    "NVIDIA Overlay"    = "NVIDIA"
    "svchost"           = "Microsoft"
    "claude"            = "Anthropic"
    "chrome"            = "Google"
    "msedge"            = "Microsoft"
    "Code"              = "Microsoft"
    "node"              = "OpenJS Foundation"
    "python"            = "Python Software Foundation"
    "ollama"            = "Ollama"
    "Spotify"           = "Spotify"
    "Discord"           = "Discord"
    "slack"             = "Slack"
    "zoom"              = "Zoom"
    "OneDrive"          = "Microsoft"
    "dropbox"           = "Dropbox"
}

# --- ADMIN CHECK --------------------------------------------------------------

function Test-IsAdmin {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# --- OUTPUT DIRECTORY ---------------------------------------------------------

function Initialize-ReportDir {
    param([string]$ModuleName)

    # v1.5: Support TRIAGE_REPORT_DIR env var from .exe wrapper
    if ($env:TRIAGE_REPORT_DIR) {
        $scanFolder = $env:TRIAGE_REPORT_DIR
    } else {
        $scriptRoot = if ($PSScriptRoot) { Split-Path $PSScriptRoot -Parent }
                      else { Split-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) -Parent }
        $logsRoot   = Join-Path $scriptRoot "Logs"
        $hostname   = $env:COMPUTERNAME
        $date       = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
        $scanFolder = Join-Path $logsRoot $hostname $date
    }

    # Reuse existing report dir within same session
    if ($Global:_TriageReportDir -and (Test-Path $Global:_TriageReportDir)) {
        return $Global:_TriageReportDir
    }

    if (-not (Test-Path $scanFolder)) {
        New-Item -ItemType Directory -Path $scanFolder -Force | Out-Null
    }
    $Global:_TriageReportDir = $scanFolder
    return $scanFolder
}

# --- SAFE DATA COLLECTION WRAPPERS -------------------------------------------

function Invoke-Safe {
    param(
        [scriptblock]$ScriptBlock,
        [string]$FallbackValue = $null
    )
    try { return & $ScriptBlock } catch { return $FallbackValue }
}

function Get-RegValue {
    param([string]$Path, [string]$Name)
    try {
        $val = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return $val.$Name
    } catch { return $null }
}

function Get-SafeEventLog {
    param(
        [string]$LogName,
        [int]$EventId,
        [int]$MaxEvents = 50,
        [datetime]$After = (Get-Date).AddDays(-30)
    )
    try {
        $filter = @{ LogName = $LogName; Id = $EventId; StartTime = $After }
        return Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop
    } catch { return @() }
}

# --- PUBLISHER VERIFICATION ---------------------------------------------------

function Get-FilePublisher {
    param([string]$FilePath)
    try {
        if (-not (Test-Path $FilePath -ErrorAction SilentlyContinue)) { return "File not found" }
        $sig = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction Stop
        if ($sig.Status -eq "Valid") {
            return $sig.SignerCertificate.Subject -replace "CN=([^,]+).*",'$1'
        } elseif ($sig.Status -eq "NotSigned") { return "UNSIGNED" }
        else { return "INVALID_SIGNATURE ($($sig.Status))" }
    } catch { return "Unknown" }
}

function Test-IsKnownPublisher {
    param([string]$Publisher)
    if ([string]::IsNullOrWhiteSpace($Publisher)) { return $false }
    foreach ($known in $KNOWN_GOOD_PUBLISHERS) {
        if ($Publisher -like "*$known*") { return $true }
    }
    return $false
}

# v1.5: Check if file path is inside a whitelisted Microsoft/browser directory
function Test-IsWhitelistedPath {
    param([string]$FilePath)
    foreach ($pattern in $WHITELISTED_APPDATA_PATHS) {
        if ($FilePath -like $pattern) { return $true }
    }
    return $false
}

# --- FLAGGING SYSTEM ---------------------------------------------------------

function New-Finding {
    param(
        [string]$Severity,
        [string]$Title,
        [string]$Detail,
        [string]$WhyItMatters,
        [string]$WhyMightBeNormal = "",
        [string]$CreatedDate = "",
        [string]$Sid = ""
    )
    return [PSCustomObject]@{
        Severity         = $Severity
        Title            = $Title
        Detail           = $Detail
        WhyItMatters     = $WhyItMatters
        WhyMightBeNormal = $WhyMightBeNormal
        CreatedDate      = $CreatedDate
        Sid              = $Sid
    }
}

# --- JSON OUTPUT (v1.5) ------------------------------------------------------
# Each module writes a .json alongside its .html for the GUI report viewer

function Write-ModuleJson {
    param(
        [string]$ReportDir,
        [string]$ModuleNumber,
        [string]$ModuleTitle,
        [array]$Findings,
        [string]$Hostname,
        [string]$ScanTime
    )
    $jsonPath = Join-Path $ReportDir "${ModuleNumber}_${ModuleTitle -replace '[^a-zA-Z0-9]','_'}.json"
    $output = @{
        module       = $ModuleNumber
        title        = $ModuleTitle
        hostname     = $Hostname
        scanTime     = $ScanTime
        version      = $TOOLKIT_VERSION
        admin        = (Test-IsAdmin)
        findings     = @($Findings | ForEach-Object {
            @{
                severity        = $_.Severity
                title           = $_.Title
                detail          = $_.Detail
                whyItMatters    = $_.WhyItMatters
                whyMightBeNormal = $_.WhyMightBeNormal
                createdDate     = $_.CreatedDate
                sid             = $_.Sid
            }
        })
        summary      = @{
            red    = @($Findings | Where-Object { $_.Severity -eq "RED" }).Count
            yellow = @($Findings | Where-Object { $_.Severity -eq "YELLOW" }).Count
            green  = @($Findings | Where-Object { $_.Severity -eq "GREEN" }).Count
            info   = @($Findings | Where-Object { $_.Severity -eq "INFO" }).Count
        }
    }
    $output | ConvertTo-Json -Depth 4 | Out-File -FilePath $jsonPath -Encoding UTF8 -Force
}

# --- HTML ENCODING ------------------------------------------------------------

function ConvertTo-HtmlEncoded {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return "" }
    $Text = $Text -replace "&",  "&amp;"
    $Text = $Text -replace "<",  "&lt;"
    $Text = $Text -replace ">",  "&gt;"
    $Text = $Text -replace '"',  "&quot;"
    $Text = $Text -replace "'",  "&#39;"
    return $Text
}

function ConvertTo-SafeHtml {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return "" }
    return ConvertTo-HtmlEncoded($Text)
}

# --- HTML GENERATION ---------------------------------------------------------

function Get-HtmlHeader {
    param(
        [string]$ModuleTitle,
        [string]$ModuleNumber,
        [string]$Hostname,
        [string]$ScanTime
    )
    return @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>[$ModuleNumber] $ModuleTitle -- $Hostname</title>
<style>
  :root {
    --bg:        #0f1117;
    --surface:   #1a1d27;
    --border:    #2a2d3a;
    --text:      #e2e8f0;
    --muted:     #64748b;
    --green:     #22c55e;
    --green-bg:  #052e16;
    --yellow:    #eab308;
    --yellow-bg: #1c1a05;
    --red:       #ef4444;
    --red-bg:    #2d0a0a;
    --blue:      #3b82f6;
    --blue-bg:   #0a1628;
    --mono:      'Courier New', monospace;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg); color: var(--text);
    font-family: 'Segoe UI', system-ui, sans-serif;
    font-size: 14px; line-height: 1.6; padding: 2rem;
  }
  .header { border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; margin-bottom: 2rem; }
  .header h1 { font-size: 1.6rem; font-weight: 700; color: var(--text); }
  .header .module-num { color: var(--blue); font-size: 0.85rem; font-weight: 600; letter-spacing: 0.1em; text-transform: uppercase; margin-bottom: 0.3rem; }
  .meta { display: flex; gap: 2rem; margin-top: 0.8rem; flex-wrap: wrap; }
  .meta-item { font-size: 0.8rem; color: var(--muted); }
  .meta-item span { color: var(--text); font-weight: 500; }
  .summary-bar { display: flex; gap: 1rem; margin-bottom: 2rem; flex-wrap: wrap; }
  .pill { padding: 0.4rem 1rem; border-radius: 999px; font-size: 0.82rem; font-weight: 600; }
  .pill-red    { background: var(--red-bg);    color: var(--red);    border: 1px solid var(--red); }
  .pill-yellow { background: var(--yellow-bg); color: var(--yellow); border: 1px solid var(--yellow); }
  .pill-green  { background: var(--green-bg);  color: var(--green);  border: 1px solid var(--green); }
  .pill-info   { background: var(--blue-bg);   color: var(--blue);   border: 1px solid var(--blue); }
  .section { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 1.5rem; overflow: hidden; }
  .section-header { padding: 0.9rem 1.2rem; background: rgba(255,255,255,0.03); border-bottom: 1px solid var(--border); cursor: pointer; display: flex; justify-content: space-between; align-items: center; user-select: none; }
  .section-header:hover { background: rgba(255,255,255,0.05); }
  .section-title { font-weight: 600; font-size: 0.95rem; }
  .section-body { padding: 1.2rem; }
  .toggle-icon { color: var(--muted); font-size: 0.8rem; }
  table { width: 100%; border-collapse: collapse; font-size: 0.82rem; }
  th { text-align: left; padding: 0.5rem 0.8rem; color: var(--muted); font-weight: 600; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 1px solid var(--border); }
  td { padding: 0.5rem 0.8rem; border-bottom: 1px solid rgba(255,255,255,0.04); vertical-align: top; word-break: break-word; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: rgba(255,255,255,0.02); }
  .mono { font-family: var(--mono); font-size: 0.8rem; }
  .badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.72rem; font-weight: 700; text-transform: uppercase; }
  .badge-red    { background: var(--red-bg);    color: var(--red); }
  .badge-yellow { background: var(--yellow-bg); color: var(--yellow); }
  .badge-green  { background: var(--green-bg);  color: var(--green); }
  .badge-info   { background: var(--blue-bg);   color: var(--blue); }
  .finding { border-radius: 6px; padding: 0.8rem 1rem; margin-bottom: 0.8rem; border-left: 3px solid; }
  .finding-red    { background: var(--red-bg);    border-color: var(--red); }
  .finding-yellow { background: var(--yellow-bg); border-color: var(--yellow); }
  .finding-green  { background: var(--green-bg);  border-color: var(--green); }
  .finding-info   { background: var(--blue-bg);   border-color: var(--blue); }
  .finding-title  { font-weight: 600; margin-bottom: 0.3rem; }
  .finding-detail { font-size: 0.82rem; color: var(--text); margin-bottom: 0.4rem; }
  .finding-why    { font-size: 0.78rem; color: var(--muted); }
  .finding-normal { font-size: 0.75rem; color: var(--muted); font-style: italic; margin-top: 0.3rem; }
  .no-findings { color: var(--muted); font-size: 0.85rem; font-style: italic; }
  code { background: rgba(255,255,255,0.06); padding: 0.1rem 0.4rem; border-radius: 3px; font-family: var(--mono); font-size: 0.8rem; }
  .footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border); font-size: 0.75rem; color: var(--muted); text-align: center; }
</style>
</head>
<body>
<div class="header">
  <div class="module-num">Module $ModuleNumber</div>
  <h1>$ModuleTitle</h1>
  <div class="meta">
    <div class="meta-item">Host: <span>$Hostname</span></div>
    <div class="meta-item">Scan time: <span>$ScanTime</span></div>
    <div class="meta-item">Toolkit: <span>v$TOOLKIT_VERSION</span></div>
    <div class="meta-item">User: <span>$env:USERNAME</span></div>
    <div class="meta-item">Admin: <span>$(if (Test-IsAdmin) { 'Yes' } else { 'NO -- some checks may be incomplete' })</span></div>
  </div>
</div>
"@
}

function Get-HtmlFooter {
    return @"
<div class="footer">
  Windows Forensic Triage Toolkit v$TOOLKIT_VERSION -- Read-only forensic tool -- No system changes made
</div>
<script>
  document.querySelectorAll('.section-header').forEach(h => {
    h.addEventListener('click', () => {
      const body = h.nextElementSibling;
      const icon = h.querySelector('.toggle-icon');
      if (body.style.display === 'none') {
        body.style.display = 'block';
        icon.textContent = '[^]';
      } else {
        body.style.display = 'none';
        icon.textContent = '[v]';
      }
    });
  });
</script>
</body>
</html>
"@
}

function Get-SeverityBadge {
    param([string]$Severity)
    $class = switch ($Severity) {
        "RED"    { "badge-red" }
        "YELLOW" { "badge-yellow" }
        "GREEN"  { "badge-green" }
        default  { "badge-info" }
    }
    return "<span class='badge $class'>$Severity</span>"
}

function ConvertTo-HtmlSection {
    param(
        [string]$Title,
        [string]$Content,
        [bool]$StartCollapsed = $false
    )
    $display = if ($StartCollapsed) { "none" } else { "block" }
    $icon    = if ($StartCollapsed) { "[v]" } else { "[^]" }
    return @"
<div class="section">
  <div class="section-header">
    <span class="section-title">$Title</span>
    <span class="toggle-icon">$icon</span>
  </div>
  <div class="section-body" style="display:$display">
    $Content
  </div>
</div>
"@
}

function ConvertTo-HtmlTable {
    param(
        [array]$Data,
        [string[]]$Headers,
        [string[]]$Properties
    )
    if (-not $Data -or $Data.Count -eq 0) {
        return "<p class='no-findings'>No data found.</p>"
    }
    $html = "<table><thead><tr>"
    foreach ($h in $Headers) { $html += "<th>$h</th>" }
    $html += "</tr></thead><tbody>"
    foreach ($row in $Data) {
        $html += "<tr>"
        foreach ($prop in $Properties) {
            $val = $row.$prop
            if ($null -eq $val) { $val = "" }
            $html += "<td class='mono'>$(ConvertTo-HtmlEncoded($val.ToString()))</td>"
        }
        $html += "</tr>"
    }
    $html += "</tbody></table>"
    return $html
}

function ConvertTo-HtmlFinding {
    param([PSCustomObject]$Finding)
    $class = switch ($Finding.Severity) {
        "RED"    { "finding-red" }
        "YELLOW" { "finding-yellow" }
        "GREEN"  { "finding-green" }
        default  { "finding-info" }
    }
    $badge  = Get-SeverityBadge -Severity $Finding.Severity
    $normal = if ($Finding.WhyMightBeNormal) {
        "<div class='finding-normal'>[i] May be normal: $($Finding.WhyMightBeNormal)</div>"
    } else { "" }
    return @"
<div class="finding $class">
  <div class="finding-title">$badge $($Finding.Title)</div>
  <div class="finding-detail">$($Finding.Detail)</div>
  <div class="finding-why">$($Finding.WhyItMatters)</div>
  $normal
</div>
"@
}

function ConvertTo-HtmlFindings {
    param([array]$Findings)
    if (-not $Findings -or $Findings.Count -eq 0) {
        return "<p class='no-findings'>[OK] No findings in this section.</p>"
    }
    $order  = @{ "RED" = 0; "YELLOW" = 1; "GREEN" = 2; "INFO" = 3 }
    $sorted = $Findings | Sort-Object { $order[$_.Severity] }
    $html   = ""
    foreach ($f in $sorted) { $html += ConvertTo-HtmlFinding -Finding $f }
    return $html
}

function Get-SummaryBar {
    param([array]$AllFindings)
    $red    = ($AllFindings | Where-Object { $_.Severity -eq "RED"    }).Count
    $yellow = ($AllFindings | Where-Object { $_.Severity -eq "YELLOW" }).Count
    $green  = ($AllFindings | Where-Object { $_.Severity -eq "GREEN"  }).Count
    $info   = ($AllFindings | Where-Object { $_.Severity -eq "INFO"   }).Count
    return @"
<div class="summary-bar">
  $(if ($red    -gt 0) { "<span class='pill pill-red'>$red Critical</span>" })
  $(if ($yellow -gt 0) { "<span class='pill pill-yellow'>$yellow Warning</span>" })
  $(if ($green  -gt 0) { "<span class='pill pill-green'>$green Clean</span>" })
  $(if ($info   -gt 0) { "<span class='pill pill-info'>$info Info</span>" })
  $(if ($red -eq 0 -and $yellow -eq 0) { "<span class='pill pill-green'>All Clear</span>" })
</div>
"@
}

Write-Host "[Common.ps1] Shared library loaded (v$TOOLKIT_VERSION)."
