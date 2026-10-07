# =============================================================================
# New-DemoScan.ps1 -- writes a synthetic scan for docs, screenshots and tests
# =============================================================================
# Produces samples\DEMO-WS01\<baseline> and \<current>, each with the
# same NN_*.json / NN_*.html files the real modules write, generated through the
# real Common.ps1 functions. Every host, user, IP and path is fictional
# (IPs are from the RFC 5737 documentation ranges).
#
# The current scan adds a scheduled task and a beacon-like connection that the
# baseline lacks, so "new since last scan" has something to show.
# =============================================================================

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$env:USERNAME = "analyst"           # Get-HtmlHeader prints the user; keep the real one out
. (Join-Path $Root "src\lib\Common.ps1") | Out-Null

$HostName = "DEMO-WS01"
$Out      = Join-Path $Root "samples\$HostName"
if (Test-Path $Out) { Remove-Item $Out -Recurse -Force }

function F($sev, $title, $detail, $why, $normal = "", $created = "") {
    New-Finding -Severity $sev -Title $title -Detail $detail -WhyItMatters $why -WhyMightBeNormal $normal -CreatedDate $created
}

function Get-DemoModules([bool]$Current) {
    $m = [ordered]@{}
    $m["01|System Identity|01_SystemIdentity"] = @(
        (F INFO  "Operating System: Windows 11 Pro 24H2 (build 26100)" "Installed 2025-11-03 | Last boot 2026-10-06 08:12 | Time zone: Eastern Standard Time" "Baseline context for every other finding."),
        (F GREEN "Secure Boot capable firmware (UEFI)" "Manufacturer: Contoso Systems | Model: CS-14 G7 | BIOS 1.22.0 (2026-04-18)" "Modern UEFI firmware supports Secure Boot and measured boot.")
    )
    $m["02|Storage & Files|02_StorageAndFiles"] = @(
        (F YELLOW "BitLocker Not Active on System Drive (C:)" "Protection status: Off | Encryption method: None" "A lost or stolen laptop exposes every file on the disk." "Some desktops in physically secured offices run unencrypted by policy."),
        (F YELLOW "Unsigned Executable in User-Writable Location" "C:\Users\jdoe\AppData\Roaming\SyncHelper\synchelper.exe | 2.1 MB | Created 2026-09-29" "Malware commonly installs to AppData because it needs no admin rights." "Some small vendors ship unsigned helpers into AppData."),
        (F GREEN "No Executables in C:\Users\Public" "Checked 412 files across Public, ProgramData and Temp" "Shared folders are a favourite drop location.")
    )
    $m["03|Security Configuration|03_SecurityConfig"] = @(
        (F GREEN "Windows Defender Real-Time Protection Is On" "Engine 1.1.24090.11 | Definitions 1.419.212.0 (updated 2026-10-06)" "Active, current antivirus is the strongest single control."),
        (F YELLOW "LSASS Is Not Running as Protected Process" "RunAsPPL = 0" "Without PPL, credential-dumping tools can read LSASS memory." "Off by default on many Windows 10 upgrades."),
        (F GREEN "UAC Enabled at Default Level" "EnableLUA = 1 | ConsentPromptBehaviorAdmin = 5" "UAC stops silent elevation.")
    )
    $m["04|Accounts & Authentication|04_AccountsAndAuth"] = @(
        (F YELLOW "Failed Login Attempts: 37 in the last 30 days" "Most from account 'administrator' via network logon (type 3), 2026-10-02 to 2026-10-05" "Bursts of failures against a built-in name suggest password guessing." "A mistyped saved password on a mapped drive can generate repeated failures."),
        (F INFO  "Administrators Group Members" "DEMO-WS01\jdoe, DEMO-WS01\Administrator (disabled)" "Every admin account is a high-value target."),
        (F GREEN "Guest Account Is Disabled" "Guest: disabled since install" "An enabled Guest account allows unauthenticated local access.")
    )
    $m["05|Processes & Software|05_ProcessesAndSoftware"] = @(
        (F RED "Known Remote Access Tool Installed: AnyDesk" "Publisher: AnyDesk Software GmbH | Version: 9.0.4 | Installed: 2026-09-28" "This software is commonly used for remote access. If the user did not install it, it may be a backdoor." "User or IT support may have installed this legitimately for remote assistance."),
        (F YELLOW "Recently Installed Software: SyncHelper" "Install date: 2026-09-29 | Publisher: (none)" "Software installed in the last 30 days should be verified against what the user intentionally installed." "Windows Update, driver installs, and user-installed software all appear here."),
        (F GREEN "No Suspicious Parent-Child Process Relationships" "Office, browsers and PDF readers have no shell or script-host children" "Office spawning PowerShell is a classic macro-malware signature.")
    )
    $p06 = @(
        (F YELLOW "Unknown Publisher in Run Key: SyncHelper" "Key: HKCU:\Software\Microsoft\Windows\CurrentVersion\Run | Value: `"C:\Users\jdoe\AppData\Roaming\SyncHelper\synchelper.exe`" --tray | Publisher: UNSIGNED" "Startup entries from unknown publishers deserve verification." "Smaller legitimate software vendors may not have widely recognized publisher names." "2026-09-29"),
        (F GREEN "No WMI Event Subscriptions" "root\subscription has no __EventFilter / consumer bindings" "WMI subscriptions are a stealthy, fileless persistence method.")
    )
    if ($Current) {
        $p06 += F RED "Scheduled Task Runs Encoded PowerShell: \Microsoft\Windows\UpdateOrchestrator\SyncCheck" "Action: powershell.exe -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA... | Runs as: SYSTEM | Trigger: every 15 minutes" "A hidden, encoded PowerShell task masquerading under a Microsoft folder is a common persistence technique." "Some management agents use encoded commands, but rarely under a Microsoft task path." "2026-10-04"
    }
    $m["06|Persistence Mechanisms|06_Persistence"] = $p06
    $m["07|Network Snapshot|07_NetworkSnapshot"] = @(
        (F GREEN "Hosts File Contains Only Standard Entries" "C:\Windows\System32\drivers\etc\hosts: comments only" "Hosts-file redirection can silently send banking or update traffic elsewhere."),
        (F YELLOW "Listening Port Open to All Interfaces: 7070/TCP" "Process: AnyDesk.exe (PID 4120) | Bound to 0.0.0.0" "Services listening on every interface are reachable from the local network." "Remote-support tools open a listener for direct connections.")
    )
    $p08 = @(
        (F INFO "Network Traffic During Monitoring Period" "Sent 18.4 MB | Received 211.7 MB over 5 minutes on Wi-Fi" "Context for judging whether any connection is unusually heavy.")
    )
    if ($Current) {
        $p08 += F RED "Persistent Connection to Suspicious Port: 203.0.113.47:4444" "Seen in 10/10 polls | Process: powershell.exe (PID 7312) | Reverse DNS: none" "A connection held open for the whole watch window to port 4444 matches default Metasploit/C2 listener behaviour." "Rare. Some lab and development tools use 4444, but not from a hidden PowerShell process."
    }
    $p08 += F YELLOW "Connection to Unidentified IP: 198.51.100.23" "Port 443 | Process: synchelper.exe | Seen in 6/10 polls | Reverse DNS: none" "Outbound traffic from an unsigned AppData binary to an IP with no DNS name deserves a look." "Content delivery networks often have no reverse DNS."
    $m["08|Network Time Series|08_NetworkTimeSeries"] = $p08
    $m["09|Forensic Artifacts|09_ForensicArtifacts"] = @(
        (F YELLOW "Security Log Cleared (Event 1102)" "2026-09-28 22:41 by DEMO-WS01\jdoe" "Attackers clear the Security log to hide their tracks." "Admins occasionally clear logs during troubleshooting."),
        (F INFO "USB Storage Devices Seen" "SanDisk Ultra USB 3.0 (first 2026-06-11, last 2026-09-28) | Kingston DataTraveler (2026-03-02)" "Removable media is both an infection and an exfiltration path.")
    )
    $corr = @(
        (F GREEN "Explained: Run key 'OneDrive' corresponds to 'Microsoft OneDrive' installed on 2026-09-12" "Install date and run key creation are within 7 days. Sources: Module 06 (run key), Module 05 (software)." "Persistence entry creation aligns with a known software installation -- expected behaviour.")
    )
    if ($Current) {
        $corr += F RED "Correlated Concern: AnyDesk installed one day before the Security log was cleared" "AnyDesk installed 2026-09-28 (Module 05); Event 1102 log cleared 2026-09-28 22:41 (Module 09); listener on 7070 (Module 07)." "A remote-access tool arriving the same day the audit trail is wiped fits a hands-on-keyboard intrusion." "Coincidence is possible if IT installed AnyDesk and later cleared logs while troubleshooting."
    }
    $m["10|Cross-Module Correlation|10_Correlation"] = $corr
    return $m
}

function Write-DemoScan([datetime]$When, [bool]$Current, [int]$Seconds) {
    $stamp = $When.ToString("yyyy-MM-dd_HH-mm-ss")
    $dir = Join-Path $Out $stamp
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $scanTime = $When.ToString("yyyy-MM-dd HH:mm:ss")
    $runs = @()
    $t = 0
    foreach ($kv in (Get-DemoModules $Current).GetEnumerator()) {
        $num, $title, $file = $kv.Key -split '\|'
        $findings = @($kv.Value)
        Write-ModuleJson -ReportDir $dir -ModuleNumber $num -ModuleTitle $title -Findings $findings -Hostname $HostName -ScanTime $scanTime
        $html  = Get-HtmlHeader -ModuleTitle $title -ModuleNumber $num -Hostname $HostName -ScanTime $scanTime
        $html += Get-SummaryBar -AllFindings $findings
        $html += ConvertTo-HtmlSection -Title "Findings & Flags" -Content (ConvertTo-HtmlFindings -Findings $findings)
        $html += "<p class='no-findings' style='margin-top:1rem'>Synthetic demo data generated by tools\New-DemoScan.ps1 -- not a real machine.</p>"
        $html += Get-HtmlFooter
        [IO.File]::WriteAllText((Join-Path $dir "$file.html"), $html, (New-Object Text.UTF8Encoding $false))
        $runs += [ordered]@{ module = $num; name = $title; outcome = "Completed"; seconds = 20 + ($num -as [int]) * 7; exitCode = 0 }
    }
    $meta = [ordered]@{
        tool = "Windows Forensic Triage Toolkit"; version = $TOOLKIT_VERSION; hostname = $HostName; user = "DEMO-WS01\analyst"
        started = $When.ToString("o"); finished = $When.AddSeconds($Seconds).ToString("o"); durationSeconds = $Seconds
        cancelled = $false; networkWatchMinutes = 5; modules = $runs
    }
    $meta | ConvertTo-Json -Depth 4 | Out-File (Join-Path $dir "scan.json") -Encoding UTF8

    $export = @(
        "WINDOWS FORENSIC TRIAGE -- HAND-OFF SUMMARY",
        "Host: $HostName   Scan: $scanTime   Toolkit: v$TOOLKIT_VERSION",
        "(Synthetic demo data -- not a real machine)",
        "",
        "CORRELATED CONCERNS"
    )
    if ($Current) {
        $export += "  [RED] AnyDesk installed 2026-09-28, Security log cleared the same night (Event 1102), listener on 7070/TCP."
        $export += "  [RED] Hidden scheduled task \Microsoft\Windows\UpdateOrchestrator\SyncCheck runs encoded PowerShell as SYSTEM every 15 min."
        $export += "  [RED] powershell.exe (PID 7312) held 203.0.113.47:4444 open for the full 5-minute watch."
    } else {
        $export += "  none"
    }
    $export += ""
    $export += "WARNINGS"
    $export += "  Unsigned synchelper.exe in AppData\Roaming, started from HKCU Run, talking to 198.51.100.23:443."
    $export += "  BitLocker off on C:. LSASS not running as PPL. 37 failed network logons against 'administrator'."
    $export += ""
    $export += "SUGGESTED NEXT STEPS"
    $export += "  1. Isolate the machine from the network before further collection."
    $export += "  2. Confirm with the user/IT whether AnyDesk and SyncHelper were installed intentionally."
    $export += "  3. Export the SyncCheck task XML and decode its -enc payload offline."
    [IO.File]::WriteAllLines((Join-Path $dir "10_Correlation_Export.txt"), [string[]]$export)
    return $dir
}

$base = Write-DemoScan -When ([datetime]"2026-09-30 09:14:05") -Current $false -Seconds 498
$cur  = Write-DemoScan -When ([datetime]"2026-10-06 16:42:31") -Current $true  -Seconds 531
Write-Host "Baseline: $base"
Write-Host "Current:  $cur"
