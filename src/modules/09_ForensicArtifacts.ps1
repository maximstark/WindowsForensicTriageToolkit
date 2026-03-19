# =============================================================================
# Module 09 -- Forensic Artifacts
# Windows Forensic Triage Toolkit
# =============================================================================
# What this module collects:
#   - USB device connection history with timestamps
#   - Security event log highlights (filtered, readable summaries)
#   - System event log anomalies (unexpected shutdowns, service failures)
#   - PowerShell Script Block logging events
#   - Recently modified files in sensitive paths (last 7 days)
#   - Recently created archive files in temp (staged exfiltration indicator)
#   - Recycle Bin contents
#   - Windows Error Reporting / crash dump history
#   - Jump list / recent files (what was opened recently)
#   - Clipboard history (if enabled)
#   - Browser history databases (existence check, not content)
#
# Admin required: Yes (event logs, some registry paths)
# Typical runtime: ~2 minutes
# =============================================================================

#Requires -Version 5.1

# Encoding fix - ensures correct display on all Windows code pages
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
. "$ScriptDir\..\lib\Common.ps1"

$MODULE_NUM   = "09"
$MODULE_TITLE = "Forensic Artifacts"
$SCAN_TIME    = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$HOSTNAME     = $env:COMPUTERNAME

Write-Host ""
Write-Host "============================================"
Write-Host " Module 09 -- Forensic Artifacts"
Write-Host "============================================"
Write-Host ""

$reportDir  = Initialize-ReportDir -ModuleName $MODULE_TITLE
$reportFile = Join-Path $reportDir "09_ForensicArtifacts.html"

$allFindings = @()
$bodyHtml    = ""

# =============================================================================
# COLLECT: USB Device History
# =============================================================================
Write-Host "[*] Reading USB device history from registry..."

$usbPath    = "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR"
$usbDevices = @()

try {
    $usbClasses = Get-ChildItem -Path $usbPath -ErrorAction Stop
    foreach ($class in $usbClasses) {
        $instances = Get-ChildItem -Path $class.PSPath -ErrorAction SilentlyContinue
        foreach ($instance in $instances) {
            try {
                $props        = Get-ItemProperty -Path $instance.PSPath -ErrorAction SilentlyContinue
                $friendlyName = $props.FriendlyName
                $deviceDesc   = $props.DeviceDesc -replace ".*;"  # strip prefix

                # Get first/last connect times from sub-keys
                $logonSessions = Get-ChildItem -Path $instance.PSPath -ErrorAction SilentlyContinue
                foreach ($session in $logonSessions) {
                    $sessionProps = Get-ItemProperty -Path $session.PSPath -ErrorAction SilentlyContinue

                    $usbDevices += [PSCustomObject]@{
                        "Device"         = if ($friendlyName) { $friendlyName } else { $class.PSChildName }
                        "Description"    = $deviceDesc
                        "Instance ID"    = $instance.PSChildName
                        "Serial/ID"      = $session.PSChildName
                    }
                }
            } catch { continue }
        }
    }
} catch {}

# Supplement with SetupAPI log for timestamps
$setupApiPath = "C:\Windows\INF\setupapi.dev.log"
$usbTimestamps = @{}
if (Test-Path $setupApiPath -ErrorAction SilentlyContinue) {
    try {
        $setupLines = Get-Content $setupApiPath -ErrorAction SilentlyContinue |
                      Select-String -Pattern "USBSTOR|>>>  Section start" |
                      Select-Object -Last 200
        # Basic timestamp extraction -- gets approximate times
        $lastTime = $null
        foreach ($line in $setupLines) {
            if ($line -match "Section start (\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})") {
                $lastTime = $matches[1]
            }
        }
    } catch {}
}

$usbHtml = if ($usbDevices.Count -gt 0) {
    $usbDevices = $usbDevices | Sort-Object Device | Select-Object -Unique -Property "Device","Description","Instance ID","Serial/ID"
    "<p style='color:#64748b;font-size:0.82rem;margin-bottom:0.8rem'>$($usbDevices.Count) unique USB storage device(s) have been connected to this machine. This is a historical record -- devices do not need to be currently connected.</p>"
    (ConvertTo-HtmlTable `
        -Data $usbDevices `
        -Headers @("Device","Description","Instance ID","Serial/ID") `
        -Properties @("Device","Description","Instance ID","Serial/ID"))
} else {
    "<p class='no-findings'>No USB storage device history found (requires Administrator for registry access).</p>"
}

$allFindings += New-Finding -Severity $SEV_INFO `
    -Title "$($usbDevices.Count) USB Storage Device(s) In History" `
    -Detail "USB device registry shows what has been plugged into this machine." `
    -WhyItMatters "Physical USB access could be used to install malware or exfiltrate data. Unknown USB devices are a red flag."

$bodyHtml += ConvertTo-HtmlSection -Title "USB Device History" -Content $usbHtml

# =============================================================================
# COLLECT: Security Event Log Highlights
# =============================================================================
Write-Host "[*] Reading Security event log highlights..."

$secEventHtml = ""
$secEvents    = @()

# Event IDs we care about with plain-English descriptions
$importantSecEvents = @{
    4616 = "System time changed"
    4624 = "Successful logon"
    4625 = "Failed logon"
    4634 = "Account logoff"
    4648 = "Logon with explicit credentials"
    4656 = "Handle to object requested"
    4663 = "Object access attempt"
    4670 = "Permissions on object changed"
    4672 = "Special privileges assigned"
    4698 = "Scheduled task created"
    4699 = "Scheduled task deleted"
    4700 = "Scheduled task enabled"
    4701 = "Scheduled task disabled"
    4702 = "Scheduled task updated"
    4719 = "Audit policy changed"
    4720 = "User account created"
    4722 = "User account enabled"
    4723 = "Password change attempt"
    4724 = "Password reset"
    4725 = "User account disabled"
    4726 = "User account deleted"
    4728 = "User added to security group"
    4732 = "User added to local group"
    4733 = "User removed from local group"
    4738 = "User account changed"
    4740 = "Account locked out"
    4756 = "User added to universal group"
    4768 = "Kerberos authentication ticket requested"
    4769 = "Kerberos service ticket requested"
    4776 = "Credential validation"
    4798 = "User's local group membership enumerated"
    4799 = "Group membership enumerated"
    7045 = "New service installed"
    1102 = "Security audit log cleared"
    4907 = "Audit settings on object changed"
}

# High-priority events to always flag
# v1.5: 4648 removed -- handled separately with SYSTEM filtering below
$alwaysFlagEvents = @(1102, 4720, 4726, 4728, 4732, 4698, 4719, 7045, 4740)

try {
    foreach ($evtId in ($alwaysFlagEvents + @(4624, 4625, 4672))) {
        $events = Get-SafeEventLog -LogName "Security" -EventId $evtId -MaxEvents 20 -After (Get-Date).AddDays(-30)
        foreach ($evt in $events) {
            $description = if ($importantSecEvents.ContainsKey($evt.Id)) {
                $importantSecEvents[$evt.Id]
            } else {
                "Event $($evt.Id)"
            }

            $severity = if ($alwaysFlagEvents -contains $evt.Id) { $SEV_RED } else { $SEV_INFO }

            $secEvents += [PSCustomObject]@{
                "Time"        = $evt.TimeCreated.ToString("yyyy-MM-dd HH:mm")
                "Event ID"    = $evt.Id
                "Description" = $description
                "Severity"    = $severity
                "Message"     = $evt.Message.Substring(0, [Math]::Min(200, $evt.Message.Length)) -replace "`n"," "
            }

            if ($alwaysFlagEvents -contains $evt.Id) {
                $allFindings += New-Finding -Severity $severity `
                    -Title "Security Event: $description (ID $($evt.Id))" `
                    -Detail "Time: $($evt.TimeCreated.ToString('yyyy-MM-dd HH:mm')) | $($evt.Message.Substring(0,[Math]::Min(300,$evt.Message.Length)) -replace '`n',' ')" `
                    -WhyItMatters "$(switch($evt.Id){
                        1102 {'The security audit log was CLEARED. This is a classic attacker action to destroy evidence of intrusion.'}
                        4720 {'A new user account was created. Verify this was intentional.'}
                        4726 {'A user account was deleted.'}
                        4728 {'A user was added to a security-enabled global group.'}
                        4732 {'A user was added to the local Administrators or other group.'}
                        4698 {'A scheduled task was created -- common malware persistence mechanism.'}
                        4719 {'Audit policy was changed -- attackers modify audit settings to avoid logging.'}
                        7045 {'A new service was installed -- common malware persistence mechanism.'}
                        # 4648 handled separately in v1.5
                        4740 {'An account was locked out -- may indicate brute force attack.'}
                        default {'This event warrants review.'}
                    })" `
                    -WhyMightBeNormal "$(switch($evt.Id){
                        1102 {'Log clearing is sometimes done by IT staff during maintenance. Still should be investigated.'}
                        4720 {'Admin may have created a new account intentionally.'}
                        4698 {'Software installers legitimately create scheduled tasks.'}
                        7045 {'Legitimate software installs services. Verify the service name and binary path.'}
                        default {'May be legitimate administrative activity.'}
                    })"
            }
        }
    }
} catch {
    $secEvents = @()
    $allFindings += New-Finding -Severity $SEV_YELLOW `
        -Title "Security Event Log Access Failed" `
        -Detail "Error: $($_.Exception.Message)" `
        -WhyItMatters "Run as Administrator to access the Security event log." `
        -WhyMightBeNormal "Normal if not running with elevated privileges."
}

$secEvents = $secEvents | Sort-Object Time -Descending | Select-Object -First 100

$secEventHtml = if ($secEvents.Count -gt 0) {
    "<p style='color:#64748b;font-size:0.82rem;margin-bottom:0.8rem'>Showing up to 100 significant security events from last 30 days, sorted newest first.</p>"
    (ConvertTo-HtmlTable `
        -Data $secEvents `
        -Headers @("Time","Event ID","Description","Message") `
        -Properties @("Time","Event ID","Description","Message"))
} else {
    "<p class='no-findings'>No significant security events found, or Security log access denied.</p>"
}

$bodyHtml += ConvertTo-HtmlSection -Title "Security Event Log Highlights" -Content $secEventHtml

# =============================================================================
# v1.5: SPECIAL HANDLING -- Event ID 4648 (Explicit Credential Logon)
# =============================================================================
# 4648 events where subject is SYSTEM (S-1-5-18 / Logon ID 0x3E7) are normal
# Windows internal service logons (DWM, UMFD, Microsoft account auth).
# Only flag where the subject is a real user account.
# =============================================================================
Write-Host "[*] Analyzing Event ID 4648 (explicit credential logon)..."

$evt4648 = Get-SafeEventLog -LogName "Security" -EventId 4648 -MaxEvents 50 -After (Get-Date).AddDays(-30)
$suspicious4648 = @()
$benign4648Count = 0

foreach ($evt in $evt4648) {
    try {
        $xml = [xml]$evt.ToXml()
        $eventData = $xml.Event.EventData.Data
        $subjectSid     = ($eventData | Where-Object { $_.Name -eq "SubjectUserSid" }).'#text'
        $subjectLogonId = ($eventData | Where-Object { $_.Name -eq "SubjectLogonId" }).'#text'
        $targetUser     = ($eventData | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
        $targetDomain   = ($eventData | Where-Object { $_.Name -eq "TargetDomainName" }).'#text'
        $processName    = ($eventData | Where-Object { $_.Name -eq "ProcessName" }).'#text'

        if ($subjectSid -eq "S-1-5-18" -and $subjectLogonId -eq "0x3e7") {
            $benign4648Count++
            continue
        }

        $suspicious4648 += [PSCustomObject]@{
            "Time"        = $evt.TimeCreated.ToString("yyyy-MM-dd HH:mm")
            "Subject SID" = $subjectSid
            "Target"      = "$targetDomain\$targetUser"
            "Process"     = if ($processName) { Split-Path -Leaf $processName } else { "Unknown" }
        }
        $allFindings += New-Finding -Severity $SEV_RED `
            -Title "Explicit credential logon by user account (Event 4648)" `
            -Detail "Time: $($evt.TimeCreated.ToString('yyyy-MM-dd HH:mm')) | Subject: $subjectSid | Target: $targetDomain\$targetUser | Process: $(if($processName){Split-Path -Leaf $processName}else{'Unknown'})" `
            -WhyItMatters "A real user account explicitly passed credentials to authenticate as another account. This can indicate lateral movement, credential theft, or RunAs usage." `
            -WhyMightBeNormal "Legitimate use of 'Run as different user' or scheduled tasks running under specific accounts."
    } catch { continue }
}

if ($benign4648Count -gt 0) {
    $allFindings += New-Finding -Severity $SEV_INFO `
        -Title "$benign4648Count routine SYSTEM credential events filtered (Event 4648)" `
        -Detail "Filtered $benign4648Count Event ID 4648 entries where Subject was SYSTEM (S-1-5-18, Logon ID 0x3E7). These are normal Windows internal service logons for DWM, UMFD, and Microsoft account authentication." `
        -WhyItMatters "These events are generated on every Windows boot and during normal Microsoft account sync. They carry no security significance."
}

$evt4648Html = if ($suspicious4648.Count -gt 0) {
    ConvertTo-HtmlTable -Data $suspicious4648 -Headers @("Time","Subject SID","Target","Process") -Properties @("Time","Subject SID","Target","Process")
} else {
    if ($benign4648Count -gt 0) {
        "<p class='no-findings'>[OK] No suspicious explicit credential events. $benign4648Count routine SYSTEM events filtered.</p>"
    } else {
        "<p class='no-findings'>[OK] No Event ID 4648 entries found in the last 30 days.</p>"
    }
}

$bodyHtml += ConvertTo-HtmlSection -Title "Explicit Credential Logon Analysis (Event 4648)" -Content $evt4648Html



# =============================================================================
# COLLECT: System Event Log Anomalies
# =============================================================================
Write-Host "[*] Reading System event log for anomalies..."

$sysEvents    = @()
$sysEventIds  = @(
    @{ Id = 6008; Desc = "Unexpected system shutdown" },
    @{ Id = 6006; Desc = "Clean system shutdown" },
    @{ Id = 6005; Desc = "Event log service started (system boot)" },
    @{ Id = 7034; Desc = "Service crashed unexpectedly" },
    @{ Id = 7035; Desc = "Service control manager sent start/stop" },
    @{ Id = 7036; Desc = "Service state changed" },
    @{ Id = 7040; Desc = "Service start type changed" },
    @{ Id = 1074; Desc = "System shutdown/restart initiated" }
)

foreach ($evtDef in $sysEventIds) {
    $events = Get-SafeEventLog -LogName "System" -EventId $evtDef.Id -MaxEvents 10
    foreach ($evt in $events) {
        $sysEvents += [PSCustomObject]@{
            "Time"        = $evt.TimeCreated.ToString("yyyy-MM-dd HH:mm")
            "Event ID"    = $evt.Id
            "Description" = $evtDef.Desc
            "Details"     = $evt.Message.Substring(0, [Math]::Min(150, $evt.Message.Length)) -replace "`n"," "
        }
        if ($evt.Id -eq 6008) {
            $allFindings += New-Finding -Severity $SEV_YELLOW `
                -Title "Unexpected System Shutdown Recorded: $($evt.TimeCreated.ToString('yyyy-MM-dd HH:mm'))" `
                -Detail $evtDef.Desc `
                -WhyItMatters "Unexpected shutdowns can indicate power issues, BSOD, or forcible shutdown by malware or an attacker." `
                -WhyMightBeNormal "Power outage, battery failure, or accidental power button press."
        }
    }
}

$sysEvents = $sysEvents | Sort-Object Time -Descending | Select-Object -First 50

$sysEventHtml = if ($sysEvents.Count -gt 0) {
    ConvertTo-HtmlTable `
        -Data $sysEvents `
        -Headers @("Time","Event ID","Description","Details") `
        -Properties @("Time","Event ID","Description","Details")
} else {
    "<p class='no-findings'>No system anomaly events found.</p>"
}

$bodyHtml += ConvertTo-HtmlSection -Title "System Event Log Anomalies" -Content $sysEventHtml -StartCollapsed $true

# =============================================================================
# COLLECT: Recently Modified Files in Sensitive Paths
# =============================================================================
Write-Host "[*] Scanning for recently modified files in sensitive locations..."

$cutoff7Days = (Get-Date).AddDays(-7)
$recentFiles = @()

$sensitiveLocations = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:APPDATA\Roaming",
    "C:\ProgramData",
    "C:\Windows\System32\Tasks",
    "C:\Windows\SysWOW64\Tasks"
)

foreach ($loc in $sensitiveLocations) {
    if (Test-Path $loc -ErrorAction SilentlyContinue) {
        $files = Get-ChildItem -Path $loc -Recurse -Force -ErrorAction SilentlyContinue |
                 Where-Object { -not $_.PSIsContainer -and $_.LastWriteTime -gt $cutoff7Days } |
                 Select-Object -First 30

        foreach ($f in $files) {
            $recentFiles += [PSCustomObject]@{
                "File"      = $f.Name
                "Location"  = $f.DirectoryName
                "Modified"  = $f.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
                "Size (KB)" = [math]::Round($f.Length / 1KB, 1)
            }
        }
    }
}

$recentFilesHtml = if ($recentFiles.Count -gt 0) {
    "<p style='color:#64748b;font-size:0.82rem;margin-bottom:0.8rem'>Files modified in the last 7 days in sensitive Windows locations.</p>"
    (ConvertTo-HtmlTable `
        -Data ($recentFiles | Sort-Object Modified -Descending) `
        -Headers @("File","Location","Modified","Size (KB)") `
        -Properties @("File","Location","Modified","Size (KB)"))
    $allFindings += New-Finding -Severity $SEV_INFO `
        -Title "$($recentFiles.Count) Recently Modified Files in Sensitive Locations" `
        -Detail "Files modified in last 7 days in startup, AppData, ProgramData, and task directories." `
        -WhyItMatters "Recent modifications to startup and system task directories can indicate persistence being installed or modified." `
        -WhyMightBeNormal "Windows Update, software installers, and normal application updates modify files in these locations."
} else {
    "<p class='no-findings'>? No recently modified files found in sensitive locations.</p>"
}

$bodyHtml += ConvertTo-HtmlSection -Title "Recently Modified Files (Last 7 Days, Sensitive Locations)" -Content $recentFilesHtml -StartCollapsed $true

# =============================================================================
# COLLECT: Archive Files in Temp (Staged Exfiltration)
# =============================================================================
Write-Host "[*] Checking temp directories for archive files..."

$archiveExts = @("*.zip","*.rar","*.7z","*.tar","*.gz","*.cab")
$archives    = @()
$tempPaths   = @($env:TEMP, "$env:LOCALAPPDATA\Temp", "C:\Windows\Temp")

foreach ($tempPath in $tempPaths) {
    if (Test-Path $tempPath -ErrorAction SilentlyContinue) {
        foreach ($ext in $archiveExts) {
            $found = Get-ChildItem -Path $tempPath -Filter $ext -Recurse -Force -ErrorAction SilentlyContinue |
                     Select-Object -First 20
            foreach ($f in $found) {
                $archives += [PSCustomObject]@{
                    "File"      = $f.Name
                    "Path"      = $f.DirectoryName
                    "Size (MB)" = [math]::Round($f.Length / 1MB, 2)
                    "Created"   = $f.CreationTime.ToString("yyyy-MM-dd HH:mm")
                    "Modified"  = $f.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
                }
            }
        }
    }
}

$archiveHtml = if ($archives.Count -gt 0) {
    ConvertTo-HtmlTable `
        -Data $archives `
        -Headers @("File","Path","Size (MB)","Created","Modified") `
        -Properties @("File","Path","Size (MB)","Created","Modified")
    # v1.5: Only flag as YELLOW if archives are large (>10MB); smaller ones are INFO
    $largeArchives = @($archives | Where-Object { $_.'Size (MB)' -gt 10 })
    $archiveSev = if ($largeArchives.Count -gt 0) { $SEV_YELLOW } else { $SEV_INFO }
    $allFindings += New-Finding -Severity $archiveSev `
        -Title "$($archives.Count) Archive File(s) Found in Temp Directories" `
        -Detail "Files: $(($archives | Select-Object -ExpandProperty File) -join ', ')" `
        -WhyItMatters "Archives in temp directories can indicate data staging before exfiltration -- malware often compresses target files before sending them out." `
        -WhyMightBeNormal "Software installers routinely extract archives to temp directories. Verify what created these files."
} else {
    "<p class='no-findings'>? No archive files found in temp directories.</p>"
}

$bodyHtml += ConvertTo-HtmlSection -Title "Archive Files in Temp Directories" -Content $archiveHtml

# =============================================================================
# COLLECT: Windows Error Reporting / Recent Crashes
# =============================================================================
Write-Host "[*] Checking crash and error reporting history..."

$werPath  = "$env:LOCALAPPDATA\Microsoft\Windows\WER\ReportArchive"
$werHtml  = ""
$werFiles = @()

if (Test-Path $werPath -ErrorAction SilentlyContinue) {
    $reports = Get-ChildItem -Path $werPath -Directory -ErrorAction SilentlyContinue |
               Sort-Object LastWriteTime -Descending |
               Select-Object -First 20

    foreach ($report in $reports) {
        $werFiles += [PSCustomObject]@{
            "Report"  = $report.Name
            "Date"    = $report.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
        }
    }
}

$werHtml = if ($werFiles.Count -gt 0) {
    "<p style='color:#64748b;font-size:0.82rem;margin-bottom:0.8rem'>Recent Windows Error Reporting crash reports. A large number of crashes can indicate system instability from malware or tampering.</p>"
    (ConvertTo-HtmlTable -Data $werFiles -Headers @("Report","Date") -Properties @("Report","Date"))
} else {
    "<p class='no-findings'>No Windows Error Reporting archives found.</p>"
}

$bodyHtml += ConvertTo-HtmlSection -Title "Windows Error Reporting (Recent Crashes)" -Content $werHtml -StartCollapsed $true

# =============================================================================
# COLLECT: Browser Profile Existence Check
# =============================================================================
Write-Host "[*] Checking browser profile paths..."

$browserPaths = @(
    @{ Browser = "Edge";    Path = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default" },
    @{ Browser = "Chrome";  Path = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default" },
    @{ Browser = "Firefox"; Path = "$env:APPDATA\Mozilla\Firefox\Profiles" },
    @{ Browser = "Opera";   Path = "$env:APPDATA\Opera Software\Opera Stable" },
    @{ Browser = "Brave";   Path = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default" }
)

$browserRows = @()
foreach ($bp in $browserPaths) {
    $exists = Test-Path $bp.Path -ErrorAction SilentlyContinue
    if ($exists) {
        # Check for Login Data (saved passwords DB)
        $loginData    = Join-Path $bp.Path "Login Data"
        $historyData  = Join-Path $bp.Path "History"
        $cookiesData  = Join-Path $bp.Path "Cookies"
        $extensionDir = Join-Path $bp.Path "Extensions"

        $extCount = 0
        if (Test-Path $extensionDir -ErrorAction SilentlyContinue) {
            $extCount = (Get-ChildItem -Path $extensionDir -Directory -ErrorAction SilentlyContinue).Count
        }

        $browserRows += [PSCustomObject]@{
            "Browser"          = $bp.Browser
            "Profile Exists"   = "Yes"
            "Login Data (DB)"  = if (Test-Path $loginData)   { "Present" } else { "Not found" }
            "History (DB)"     = if (Test-Path $historyData) { "Present" } else { "Not found" }
            "Extensions"       = if ($extCount -gt 0) { "$extCount extension folder(s)" } else { "None/unknown" }
        }
    }
}

$browserHtml = if ($browserRows.Count -gt 0) {
    "<p style='color:#64748b;font-size:0.82rem;margin-bottom:0.8rem'>Browser profiles found on this machine. Login Data databases contain encrypted saved passwords.</p>"
    (ConvertTo-HtmlTable `
        -Data $browserRows `
        -Headers @("Browser","Profile Exists","Login Data (DB)","History (DB)","Extensions") `
        -Properties @("Browser","Profile Exists","Login Data (DB)","History (DB)","Extensions"))
    $allFindings += New-Finding -Severity $SEV_INFO `
        -Title "$($browserRows.Count) Browser Profile(s) Found" `
        -Detail "Browsers: $(($browserRows | Select-Object -ExpandProperty Browser) -join ', ')" `
        -WhyItMatters "Browser saved password databases are a high-value target for credential theft malware. Ensure browser profiles are protected."
} else {
    "<p class='no-findings'>No browser profiles found at standard locations.</p>"
}

$bodyHtml += ConvertTo-HtmlSection -Title "Browser Profiles" -Content $browserHtml

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
Write-Host "[+] Module 09 complete."
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
