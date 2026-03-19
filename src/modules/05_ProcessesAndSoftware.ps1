# =============================================================================
# Module 05 -- Processes & Software
# Windows Forensic Triage Toolkit
# =============================================================================
# What this module collects:
#   - All running processes with publisher verification
#   - Processes running from suspicious/unusual locations
#   - Processes with no publisher (unsigned)
#   - RAT name matching against running processes
#   - Parent-child process anomalies (e.g. Word spawning PowerShell)
#   - All installed programs with install dates
#   - Recently installed software (last 30 days)
#   - Known remote access / RAT names in installed programs
#   - Running processes with active network connections
#
# Admin required: No (all available to standard user)
# Typical runtime: ~60 seconds
# =============================================================================

#Requires -Version 5.1

# Encoding fix - ensures correct display on all Windows code pages
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
. "$ScriptDir\..\lib\Common.ps1"

$MODULE_NUM   = "05"
$MODULE_TITLE = "Processes & Software"
$SCAN_TIME    = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$HOSTNAME     = $env:COMPUTERNAME

Write-Host ""
Write-Host "============================================"
Write-Host " Module 05 -- Processes & Software"
Write-Host "============================================"
Write-Host ""

$reportDir  = Initialize-ReportDir -ModuleName $MODULE_TITLE
$reportFile = Join-Path $reportDir "05_ProcessesAndSoftware.html"

$allFindings = @()
$bodyHtml    = ""

# Suspicious parent-child process combinations
# Key = parent process, Value = child processes that are suspicious from that parent
$SUSPICIOUS_PARENT_CHILD = @{
    "winword"     = @("powershell","cmd","wscript","cscript","mshta","regsvr32","rundll32","certutil")
    "excel"       = @("powershell","cmd","wscript","cscript","mshta","regsvr32","rundll32","certutil")
    "outlook"     = @("powershell","cmd","wscript","cscript","mshta","regsvr32","rundll32")
    "acrobat"     = @("powershell","cmd","wscript","cscript")
    "acrord32"    = @("powershell","cmd","wscript","cscript")
    "iexplore"    = @("powershell","cmd","wscript","cscript","mshta")
    "chrome"      = @("powershell","cmd","wscript")
    "firefox"     = @("powershell","cmd","wscript")
    "msedge"      = @("powershell","cmd","wscript")
    "notepad"     = @("powershell","cmd","net","netsh","reg")
}

# Paths where processes should NOT normally run from
$SUSPICIOUS_PROC_PATHS = @(
    $env:TEMP,
    "$env:LOCALAPPDATA\Temp",
    "C:\Windows\Temp",
    "$env:PUBLIC",
    "C:\ProgramData\Microsoft\Windows\Start Menu",
    "$env:APPDATA\Microsoft\Windows\Start Menu"
)

# =============================================================================
# COLLECT: Running Processes
# =============================================================================
Write-Host "[*] Enumerating running processes..."

# Get all active TCP connections for cross-reference
$activeConnections = Invoke-Safe {
    Get-NetTCPConnection -State Established -ErrorAction Stop |
    Group-Object OwningProcess |
    Select-Object Name, Count
}
$connectedPIDs = if ($activeConnections) {
    $activeConnections | ForEach-Object { [int]$_.Name }
} else { @() }

$processes = Get-Process -ErrorAction SilentlyContinue
$procRows  = @()
$flaggedProcs = 0

foreach ($proc in $processes) {
    try {
        $path      = $proc.MainModule.FileName
        $publisher = if ($path) { Get-FilePublisher -FilePath $path } else { "No path (kernel/system)" }
        $isKnown   = Test-IsKnownPublisher -Publisher $publisher
        $hasNet    = $connectedPIDs -contains $proc.Id
        $isSusp    = $false
        $flagReason= ""

        # Check for RAT name match
        foreach ($rat in $KNOWN_RAT_NAMES) {
            if ($proc.Name -like "*$rat*") {
                $isSusp     = $true
                $flagReason = "Matches known RAT/remote access tool name"
                break
            }
        }

        # Check for process running from suspicious location
        if ($path) {
            foreach ($suspPath in $SUSPICIOUS_PROC_PATHS) {
                if ($path -like "$suspPath*") {
                    $isSusp     = $true
                    $flagReason = "Running from suspicious location: $suspPath"
                    break
                }
            }
        }

        # Unsigned executable running with network connection
        if ($publisher -eq "UNSIGNED" -and $hasNet) {
            $isSusp     = $true
            $flagReason = "Unsigned process with active network connection"
        }

        if ($isSusp) {
            $flaggedProcs++
            $allFindings += New-Finding `
                -Severity $SEV_RED `
                -Title "Suspicious Process: $($proc.Name) (PID $($proc.Id))" `
                -Detail "Path: $path | Publisher: $publisher | Reason: $flagReason | Network: $hasNet" `
                -WhyItMatters "This process matches one or more indicators associated with malicious software." `
                -WhyMightBeNormal "Verify the process against its expected install location and publisher."
        }

        $procRows += [PSCustomObject]@{
            "PID"         = $proc.Id
            "Name"        = $proc.Name
            "CPU (s)"     = [math]::Round($proc.TotalProcessorTime.TotalSeconds, 1)
            "RAM (MB)"    = [math]::Round($proc.WorkingSet64 / 1MB, 1)
            "Net Active"  = if ($hasNet) { "YES" } else { "" }
            "Publisher"   = $publisher
            "Path"        = if ($path) { $path } else { "(system)" }
            "Flag"        = if ($isSusp) { "?? $flagReason" } else { "" }
        }
    } catch {
        $procRows += [PSCustomObject]@{
            "PID"        = $proc.Id
            "Name"       = $proc.Name
            "CPU (s)"    = 0
            "RAM (MB)"   = 0
            "Net Active" = ""
            "Publisher"  = "Access denied"
            "Path"       = "(access denied)"
            "Flag"       = ""
        }
    }
}

# Sort: flagged first, then by name
$procRows = $procRows | Sort-Object { if ($_.Flag) { 0 } else { 1 } }, Name

$procHtml = "<p style='color:#64748b;font-size:0.82rem;margin-bottom:0.8rem'>$($procRows.Count) processes | $flaggedProcs flagged | Processes with active network connections highlighted.</p>"
$procHtml += ConvertTo-HtmlTable `
    -Data $procRows `
    -Headers @("PID","Name","CPU (s)","RAM (MB)","Network","Publisher","Path","Flag") `
    -Properties @("PID","Name","CPU (s)","RAM (MB)","Net Active","Publisher","Path","Flag")

if ($flaggedProcs -eq 0) {
    $allFindings += New-Finding -Severity $SEV_GREEN `
        -Title "No Suspicious Processes Detected" `
        -Detail "All $($procRows.Count) running processes passed publisher and location checks." `
        -WhyItMatters "No known remote access tools or suspicious executables are currently running."
}

$bodyHtml += ConvertTo-HtmlSection -Title "Running Processes" -Content $procHtml

# =============================================================================
# COLLECT: Parent-Child Process Anomaly Check
# =============================================================================
Write-Host "[*] Checking parent-child process relationships..."

$parentChildHtml     = ""
$parentChildFindings = @()

try {
    $wmiProcs = Get-CimInstance Win32_Process -ErrorAction Stop
    $procDict = @{}
    foreach ($p in $wmiProcs) { $procDict[$p.ProcessId] = $p }

    foreach ($proc in $wmiProcs) {
        $parentId   = $proc.ParentProcessId
        $parentProc = $procDict[$parentId]
        if (-not $parentProc) { continue }

        $childName  = $proc.Name.ToLower() -replace "\.exe$",""
        $parentName = $parentProc.Name.ToLower() -replace "\.exe$",""

        if ($SUSPICIOUS_PARENT_CHILD.ContainsKey($parentName)) {
            if ($SUSPICIOUS_PARENT_CHILD[$parentName] -contains $childName) {
                $parentChildFindings += [PSCustomObject]@{
                    "Parent"    = "$($parentProc.Name) (PID $parentId)"
                    "Child"     = "$($proc.Name) (PID $($proc.ProcessId))"
                    "Child Path"= $proc.ExecutablePath
                    "Severity"  = "HIGH"
                }
                $allFindings += New-Finding -Severity $SEV_RED `
                    -Title "Suspicious Parent-Child: $($parentProc.Name) -> $($proc.Name)" `
                    -Detail "Parent PID: $parentId | Child PID: $($proc.ProcessId) | Child path: $($proc.ExecutablePath)" `
                    -WhyItMatters "Office applications, PDF readers, and browsers spawning shells or script interpreters is a classic malware indicator. This is how macro-based malware executes." `
                    -WhyMightBeNormal "Some legitimate automation tools use this pattern. Verify the child process path and what it is doing."
            }
        }
    }

    if ($parentChildFindings.Count -gt 0) {
        $parentChildHtml = ConvertTo-HtmlTable `
            -Data $parentChildFindings `
            -Headers @("Parent","Child","Child Path","Severity") `
            -Properties @("Parent","Child","Child Path","Severity")
    } else {
        $parentChildHtml = "<p class='no-findings'>? No suspicious parent-child process relationships detected.</p>"
        $allFindings += New-Finding -Severity $SEV_GREEN `
            -Title "No Suspicious Parent-Child Process Relationships" `
            -Detail "No Office/browser applications are spawning shells or script interpreters." `
            -WhyItMatters "Macro-based malware commonly executes by making Word or Excel spawn a command shell."
    }
} catch {
    $parentChildHtml = "<p class='no-findings'>Could not analyze process relationships: $($_.Exception.Message)</p>"
}

$bodyHtml += ConvertTo-HtmlSection -Title "Parent-Child Process Anomalies" -Content $parentChildHtml

# =============================================================================
# COLLECT: Installed Programs
# =============================================================================
Write-Host "[*] Enumerating installed programs..."

$regPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

$installedProgs = @()
$cutoff30       = (Get-Date).AddDays(-30)

foreach ($regPath in $regPaths) {
    try {
        $items = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue |
                 Where-Object { $_.DisplayName -and $_.DisplayName.Trim() -ne "" }

        foreach ($item in $items) {
            $installDate = $null
            if ($item.InstallDate -and $item.InstallDate -match "^\d{8}$") {
                try {
                    $installDate = [datetime]::ParseExact($item.InstallDate, "yyyyMMdd", $null)
                } catch {}
            }

            $isRecent = $installDate -and $installDate -gt $cutoff30
            $isRAT    = $false
            foreach ($rat in $KNOWN_RAT_NAMES) {
                if ($item.DisplayName -like "*$rat*") { $isRAT = $true; break }
            }

            $installedProgs += [PSCustomObject]@{
                "Name"        = $item.DisplayName
                "Version"     = $item.DisplayVersion
                "Publisher"   = $item.Publisher
                "Install Date"= if ($installDate) { $installDate.ToString("yyyy-MM-dd") } else { "Unknown" }
                "Recent"      = if ($isRecent) { "?? NEW" } else { "" }
                "RAT Flag"    = if ($isRAT) { "? REVIEW" } else { "" }
            }

            if ($isRAT) {
                $allFindings += New-Finding -Severity $SEV_RED `
                    -Title "Known Remote Access Tool Installed: $($item.DisplayName)" `
                    -Detail "Publisher: $($item.Publisher) | Version: $($item.DisplayVersion) | Installed: $(if($installDate){$installDate.ToString('yyyy-MM-dd')}else{'Unknown'})" `
                    -WhyItMatters "This software is commonly used for remote access. If the user did not install it, it may be a backdoor." `
                    -WhyMightBeNormal "User or IT support may have installed this legitimately for remote assistance."
            }

            if ($isRecent -and -not $isRAT) {
                # v1.5: Only YELLOW if publisher is unknown; INFO for known publishers
                $recentSev = if (-not $item.Publisher -or (Test-IsKnownPublisher $item.Publisher)) { $SEV_INFO } else { $SEV_YELLOW }
                $allFindings += New-Finding -Severity $recentSev `
                    -Title "Recently Installed Software: $($item.DisplayName)" `
                    -Detail "Install date: $($installDate.ToString('yyyy-MM-dd')) | Publisher: $($item.Publisher)" `
                    -WhyItMatters "Software installed in the last 30 days should be verified against what the user intentionally installed." `
                    -WhyMightBeNormal "Windows Update, driver installs, and user-installed software all appear here."
            }
        }
    } catch { continue }
}

# Deduplicate by name
$installedProgs = $installedProgs | Sort-Object Name -Unique

$progHtml = "<p style='color:#64748b;font-size:0.82rem;margin-bottom:0.8rem'>$($installedProgs.Count) installed programs found.</p>"
$progHtml += ConvertTo-HtmlTable `
    -Data ($installedProgs | Sort-Object { if ($_.RAT_Flag) { 0 } elseif ($_.Recent) { 1 } else { 2 } }, Name) `
    -Headers @("Name","Version","Publisher","Install Date","Recent?","RAT Flag") `
    -Properties @("Name","Version","Publisher","Install Date","Recent","RAT Flag")

$bodyHtml += ConvertTo-HtmlSection -Title "Installed Programs" -Content $progHtml

# =============================================================================
# COLLECT: Processes With Network Connections
# =============================================================================
Write-Host "[*] Mapping network-connected processes..."

$netProcHtml = ""
try {
    $conns = Get-NetTCPConnection -State Established -ErrorAction Stop
    $netProcs = $conns | ForEach-Object {
        $pid_    = $_.OwningProcess
        $proc_   = Get-Process -Id $pid_ -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            "Process"       = if ($proc_) { $proc_.Name } else { "PID $pid_" }
            "PID"           = $pid_
            "Local Port"    = $_.LocalPort
            "Remote IP"     = $_.RemoteAddress
            "Remote Port"   = $_.RemotePort
            "State"         = $_.State
        }
    } | Sort-Object Process

    if ($netProcs.Count -gt 0) {
        $netProcHtml = ConvertTo-HtmlTable `
            -Data $netProcs `
            -Headers @("Process","PID","Local Port","Remote IP","Remote Port","State") `
            -Properties @("Process","PID","Local Port","Remote IP","Remote Port","State")

        # Flag connections to suspicious ports
        foreach ($nc in $netProcs) {
            if ($SUSPICIOUS_PORTS -contains $nc.'Remote Port') {
                $allFindings += New-Finding -Severity $SEV_RED `
                    -Title "Connection to Suspicious Port: $($nc.'Remote Port')" `
                    -Detail "Process: $($nc.Process) (PID $($nc.PID)) -> $($nc.'Remote IP'):$($nc.'Remote Port')" `
                    -WhyItMatters "Port $($nc.'Remote Port') is commonly used by reverse shells and C2 frameworks (Metasploit, Cobalt Strike)." `
                    -WhyMightBeNormal "Some legitimate software uses non-standard ports. Verify the remote IP ownership."
            }
        }
    } else {
        $netProcHtml = "<p class='no-findings'>No established outbound connections at time of scan.</p>"
    }
} catch {
    $netProcHtml = "<p class='no-findings'>Could not retrieve network connections: $($_.Exception.Message)</p>"
}

$bodyHtml += ConvertTo-HtmlSection -Title "Processes With Active Network Connections" -Content $netProcHtml

# =============================================================================
# ASSEMBLE REPORT
# =============================================================================
Write-Host "[*] Writing report..."

$summaryHtml     = Get-SummaryBar -AllFindings $allFindings
$findingsHtml    = ConvertTo-HtmlFindings -Findings $allFindings
$findingsSection = ConvertTo-HtmlSection -Title "Findings & Flags" -Content $findingsHtml

$fullHtml  = (Get-HtmlHeader -ModuleTitle $MODULE_TITLE -ModuleNumber $MODULE_NUM -Hostname $HOSTNAME -ScanTime $SCAN_TIME)
$fullHtml += $summaryHtml
$fullHtml += $findingsSection
$fullHtml += $bodyHtml
$fullHtml += Get-HtmlFooter

$fullHtml | Out-File -FilePath $reportFile -Encoding UTF8 -Force

Write-Host ""
Write-Host "[+] Module 05 complete."
Write-Host "    Report saved to: $reportFile"
Write-Host ""


# v1.5: Write JSON output for GUI report viewer
Write-ModuleJson -ReportDir $reportDir -ModuleNumber $MODULE_NUM -ModuleTitle $MODULE_TITLE `
    -Findings $allFindings -Hostname $HOSTNAME -ScanTime $SCAN_TIME

return @{
    Module = $MODULE_TITLE
    Red    = ($allFindings | Where-Object { $_.Severity -eq "RED"    }).Count
    Yellow = ($allFindings | Where-Object { $_.Severity -eq "YELLOW" }).Count
    Report = $reportFile
}
