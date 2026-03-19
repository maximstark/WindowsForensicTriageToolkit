# =============================================================================
# Module 06 -- Persistence Mechanisms
# Windows Forensic Triage Toolkit
# =============================================================================
# What this module collects:
#   - Registry Run / RunOnce keys (all users)
#   - Winlogon entries (shell replacement, userinit hijack)
#   - Image File Execution Options (debugger hijack -- very stealthy)
#   - Scheduled tasks with full action details + encoded command detection
#   - Services -- all with binary path verification
#   - WMI event subscriptions (advanced persistence)
#   - Boot Configuration Data (bcdedit)
#   - Active Setup installed components
#   - Browser extensions (Edge, Chrome, Firefox)
#
# Admin required: Yes (some registry paths and WMI require elevation)
# Typical runtime: ~90 seconds
# =============================================================================

#Requires -Version 5.1

# Encoding fix - ensures correct display on all Windows code pages
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
. "$ScriptDir\..\lib\Common.ps1"

$MODULE_NUM   = "06"
$MODULE_TITLE = "Persistence Mechanisms"
$SCAN_TIME    = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$HOSTNAME     = $env:COMPUTERNAME

Write-Host ""
Write-Host "============================================"
Write-Host " Module 06 -- Persistence Mechanisms"
Write-Host "============================================"
Write-Host ""

$reportDir  = Initialize-ReportDir -ModuleName $MODULE_TITLE
$reportFile = Join-Path $reportDir "06_Persistence.html"

$allFindings = @()
$bodyHtml    = ""

# =============================================================================
# COLLECT: Registry Run Keys
# =============================================================================
Write-Host "[*] Checking registry run keys..."

$runKeyPaths = @(
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
)

$runEntries = @()
foreach ($regPath in $runKeyPaths) {
    try {
        $props = Get-ItemProperty -Path $regPath -ErrorAction Stop
        # Task 6: Get the registry key's last write time for createdDate field
        $keyItem      = Get-Item -Path $regPath -ErrorAction SilentlyContinue
        $keyLastWrite = if ($keyItem -and $keyItem.LastWriteTime) { $keyItem.LastWriteTime.ToString("yyyy-MM-dd") } else { "" }
        $props.PSObject.Properties |
            Where-Object { $_.Name -notmatch "^PS" } |
            ForEach-Object {
                $val       = $_.Value.ToString()
                # Extract executable path from value (may have arguments)
                $exePath   = ($val -split '"')[1]
                if (-not $exePath) { $exePath = ($val -split ' ')[0] }
                # Task 4: Gate -- only run the missing-file check if the value looks like a file path.
                # Avoids false "FILE NOT FOUND" alerts on non-path registry values (GUIDs, flags, etc.)
                $looksLikePath = ($val -match '\\') -or
                                 ($val -match '^[A-Za-z]:') -or
                                 ($val -match '^%') -or
                                 ($val -match '\.(exe|dll|bat|cmd|ps1|vbs|js)(\s|"|$)')
                $publisher = if ($exePath -and (Test-Path $exePath -ErrorAction SilentlyContinue)) {
                    Get-FilePublisher -FilePath $exePath
                } elseif ($looksLikePath -and $exePath -and -not (Test-Path ($exePath -replace '"',''))) {
                    "FILE NOT FOUND"
                } else {
                    "Could not verify"
                }
                $isKnown = Test-IsKnownPublisher -Publisher $publisher

                $runEntries += [PSCustomObject]@{
                    "Registry Key" = $regPath
                    "Name"         = $_.Name
                    "Value"        = $val
                    "Publisher"    = $publisher
                    "Known"        = if ($isKnown) { "Yes" } elseif ($publisher -eq "FILE NOT FOUND") { "?? MISSING" } else { "UNKNOWN" }
                }

                if ($publisher -eq "FILE NOT FOUND") {
                    $allFindings += New-Finding -Severity $SEV_YELLOW `
                        -Title "Run Key Points to Missing File: $($_.Name)" `
                        -Detail "Key: $regPath | Value: $val" `
                        -WhyItMatters "An orphaned run key can indicate malware that was deleted but left its persistence entry. It can also indicate partial cleanup." `
                        -WhyMightBeNormal "Common after uninstalling software that doesn't clean up its registry entries." `
                        -CreatedDate $keyLastWrite
                } elseif (-not $isKnown -and $publisher -ne "FILE NOT FOUND" -and $publisher -ne "No path (kernel/system)") {
                    $allFindings += New-Finding -Severity $SEV_YELLOW `
                        -Title "Unknown Publisher in Run Key: $($_.Name)" `
                        -Detail "Key: $regPath | Value: $val | Publisher: $publisher" `
                        -WhyItMatters "Startup entries from unknown publishers deserve verification. Legitimate software from known vendors is expected here." `
                        -WhyMightBeNormal "Smaller legitimate software vendors may not have widely recognized publisher names." `
                        -CreatedDate $keyLastWrite
                }
            }
    } catch { continue }
}

$runHtml = if ($runEntries.Count -gt 0) {
    ConvertTo-HtmlTable `
        -Data $runEntries `
        -Headers @("Registry Key","Name","Value","Publisher","Known") `
        -Properties @("Registry Key","Name","Value","Publisher","Known")
} else {
    "<p class='no-findings'>? No entries found in Run registry keys.</p>"
}

$bodyHtml += ConvertTo-HtmlSection -Title "Registry Run Keys" -Content $runHtml

# =============================================================================
# COLLECT: Image File Execution Options (Debugger Hijack)
# =============================================================================
Write-Host "[*] Checking Image File Execution Options (debugger hijack)..."

$ifeoPath    = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
$ifeoEntries = @()

try {
    $ifeoKeys = Get-ChildItem -Path $ifeoPath -ErrorAction Stop
    foreach ($key in $ifeoKeys) {
        $debugger = Get-RegValue -Path $key.PSPath -Name "Debugger"
        if ($debugger) {
            $ifeoEntries += [PSCustomObject]@{
                "Target Executable" = $key.PSChildName
                "Debugger Value"    = $debugger
                "Risk"              = "HIGH -- Any launch of this executable runs the debugger instead"
            }
            # Any debugger set on a non-development machine is highly suspicious
            $allFindings += New-Finding -Severity $SEV_RED `
                -Title "Image File Execution Options Debugger Set: $($key.PSChildName)" `
                -Detail "Whenever '$($key.PSChildName)' is launched, '$debugger' runs instead." `
                -WhyItMatters "This is a classic malware persistence technique. The legitimate program never runs -- the attacker's code runs in its place every time the user launches the target application." `
                -WhyMightBeNormal "Legitimate on developer machines with Visual Studio or debugging tools. Almost never legitimate on a personal/home machine."
        }
    }
} catch {}

$ifeoHtml = if ($ifeoEntries.Count -gt 0) {
    ConvertTo-HtmlTable `
        -Data $ifeoEntries `
        -Headers @("Target Executable","Debugger Value","Risk") `
        -Properties @("Target Executable","Debugger Value","Risk")
} else {
    "<p class='no-findings'>? No debugger hijacks found in Image File Execution Options.</p>"
    $allFindings += New-Finding -Severity $SEV_GREEN `
        -Title "No Debugger Hijacks in Image File Execution Options" `
        -Detail "No IFEO debugger values are set." `
        -WhyItMatters "IFEO hijacks are a stealthy persistence technique that runs attacker code every time a specific program is launched."
}

$bodyHtml += ConvertTo-HtmlSection -Title "Image File Execution Options (Debugger Hijack Check)" -Content $ifeoHtml

# =============================================================================
# COLLECT: Scheduled Tasks
# =============================================================================
Write-Host "[*] Enumerating scheduled tasks..."

$taskEntries  = @()
$encodedTasks = 0

try {
    $tasks = Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.State -ne "Disabled" }

    foreach ($task in $tasks) {
        try {
            $action    = $task.Actions | Select-Object -First 1
            $execute   = if ($action) { $action.Execute } else { "" }
            $arguments = if ($action) { $action.Arguments } else { "" }
            $publisher       = ""
            $isEncoded       = $false
            $isSusp          = $false
            $flagReason      = ""
            # Task 6: Get task registration date for createdDate field
            $taskCreatedDate = ""
            try {
                $taskXml = [xml]($task | Export-ScheduledTask -ErrorAction Stop)
                $regDate = $taskXml.Task.RegistrationInfo.Date
                if ($regDate) { $taskCreatedDate = $regDate.Split('T')[0] }
            } catch {}
            # Task 6: Capture principal for cross-module correlation
            $principalId = if ($task.Principal -and $task.Principal.UserId) { $task.Principal.UserId } else { "" }

            # Check for encoded commands
            if ($arguments -match "-[Ee]nc(odedCommand)?\s+[A-Za-z0-9+/]{20,}") {
                $isEncoded  = $true
                $isSusp     = $true
                $encodedTasks++
                $flagReason = "Contains Base64 encoded command"
            }

            # Check for download cradles in arguments
            if ($arguments -match "DownloadString|DownloadFile|IEX|Invoke-Expression|WebClient|BitsTransfer") {
                $isSusp     = $true
                $flagReason = "Contains download/execution pattern"
            }

            # Check for temp directory execution
            if ($execute -match [regex]::Escape($env:TEMP) -or
                $execute -match "\\Temp\\" -or
                $execute -match "\\AppData\\") {
                $isSusp     = $true
                $flagReason = "Runs from temporary/AppData location"
            }

            # Verify publisher if we have a path
            if ($execute -and (Test-Path $execute -ErrorAction SilentlyContinue)) {
                $publisher = Get-FilePublisher -FilePath $execute
            } elseif ($execute) {
                $publisher = "File not found"
            }

            # Skip known Microsoft/Windows tasks unless suspicious
            $isWindowsTask = $task.TaskPath -match "\\Microsoft\\Windows\\" -or
                             $task.TaskPath -match "\\Microsoft\\Office\\"
            if ($isWindowsTask -and -not $isSusp) { continue }

            $taskEntries += [PSCustomObject]@{
                "Task Name"  = $task.TaskName
                "Path"       = $task.TaskPath
                "Execute"    = $execute
                "Arguments"  = if ($arguments.Length -gt 80) { $arguments.Substring(0,80) + "..." } else { $arguments }
                "State"      = $task.State
                "Publisher"  = $publisher
                "Flag"       = if ($isSusp) { "?? $flagReason" } else { "" }
            }

            if ($isSusp) {
                $allFindings += New-Finding -Severity $SEV_RED `
                    -Title "Suspicious Scheduled Task: $($task.TaskName)" `
                    -Detail "Execute: $execute | Args: $($arguments.Substring(0, [Math]::Min(200, $arguments.Length))) | Reason: $flagReason | Principal: $principalId" `
                    -WhyItMatters "Scheduled tasks are a common malware persistence mechanism. Encoded commands hide malicious intent." `
                    -WhyMightBeNormal "Some legitimate software uses scheduled tasks with complex arguments. Verify the task source." `
                    -CreatedDate $taskCreatedDate
            }
        } catch { continue }
    }
} catch {
    $taskEntries = @()
}

$taskHtml = if ($taskEntries.Count -gt 0) {
    "<p style='color:#64748b;font-size:0.82rem;margin-bottom:0.8rem'>Showing non-Windows scheduled tasks. Windows system tasks are filtered unless flagged.</p>"
    (ConvertTo-HtmlTable `
        -Data $taskEntries `
        -Headers @("Task Name","Path","Execute","Arguments","State","Publisher","Flag") `
        -Properties @("Task Name","Path","Execute","Arguments","State","Publisher","Flag"))
} else {
    "<p class='no-findings'>? No suspicious scheduled tasks found. All non-Windows tasks passed checks.</p>"
}

if ($encodedTasks -eq 0 -and $taskEntries.Count -eq 0) {
    $allFindings += New-Finding -Severity $SEV_GREEN `
        -Title "No Suspicious Scheduled Tasks Detected" `
        -Detail "No encoded commands, download cradles, or temp-directory executions found in scheduled tasks." `
        -WhyItMatters "Scheduled tasks are a primary malware persistence mechanism."
}

$bodyHtml += ConvertTo-HtmlSection -Title "Scheduled Tasks (Non-Windows, Flagged)" -Content $taskHtml

# =============================================================================
# COLLECT: WMI Event Subscriptions
# =============================================================================
Write-Host "[*] Checking WMI event subscriptions..."

$wmiHtml = ""
try {
    $filters   = @(Get-CimInstance -Namespace root\subscription -ClassName __EventFilter   -ErrorAction Stop)
    $consumers = @(Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction Stop)
    $bindings  = @(Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction Stop)

    if ($filters.Count -gt 0 -or $consumers.Count -gt 0 -or $bindings.Count -gt 0) {
        $wmiHtml = "<p style='color:#ef4444;font-weight:600;margin-bottom:0.8rem'>?? WMI event subscriptions detected! This is unusual on a home machine and is a known advanced persistence technique.</p>"

        $wmiRows = @()
        foreach ($f in $filters) {
            $wmiRows += [PSCustomObject]@{
                "Type"  = "Event Filter"
                "Name"  = $f.Name
                "Query" = $f.Query
                "Namespace" = $f.EventNameSpace
            }
        }
        foreach ($c in $consumers) {
            $wmiRows += [PSCustomObject]@{
                "Type"  = "Event Consumer ($($c.CimClass.CimClassName))"
                "Name"  = $c.Name
                "Query" = if ($c.CommandLineTemplate) { $c.CommandLineTemplate } elseif ($c.ScriptText) { $c.ScriptText } else { "" }
                "Namespace" = ""
            }
        }
        $wmiHtml += ConvertTo-HtmlTable `
            -Data $wmiRows `
            -Headers @("Type","Name","Query/Command","Namespace") `
            -Properties @("Type","Name","Query","Namespace")

        $allFindings += New-Finding -Severity $SEV_RED `
            -Title "WMI Event Subscriptions Found ($($filters.Count) filter(s), $($consumers.Count) consumer(s))" `
            -Detail "Filters: $(($filters | Select-Object -ExpandProperty Name) -join ', ') | Consumers: $(($consumers | Select-Object -ExpandProperty Name) -join ', ')" `
            -WhyItMatters "WMI subscriptions execute code in response to system events and survive reboots. This technique is used by APT groups and sophisticated malware because it is invisible to most AV scans." `
            -WhyMightBeNormal "Extremely rare on home machines. Enterprise management software (SCCM, etc.) uses WMI subscriptions legitimately."
    } else {
        $wmiHtml = "<p class='no-findings'>? No WMI event subscriptions found. This is the expected state on a home machine.</p>"
        $allFindings += New-Finding -Severity $SEV_GREEN `
            -Title "No WMI Event Subscriptions" `
            -Detail "WMI subscription namespaces are empty." `
            -WhyItMatters "WMI subscriptions are an advanced persistence mechanism used by sophisticated attackers."
    }
} catch {
    $wmiHtml = "<p class='no-findings'>Could not query WMI subscriptions: $($_.Exception.Message). Requires Administrator.</p>"
}

$bodyHtml += ConvertTo-HtmlSection -Title "WMI Event Subscriptions" -Content $wmiHtml

# =============================================================================
# COLLECT: Services
# =============================================================================
Write-Host "[*] Enumerating services..."

$serviceEntries = @()
try {
    $services = Get-CimInstance Win32_Service -ErrorAction Stop |
                Where-Object { $_.StartMode -ne "Disabled" -and $_.State -eq "Running" }

    foreach ($svc in $services) {
        $binPath   = $svc.PathName -replace '"','' -replace ' .*$',''  # extract exe path
        $publisher = if ($binPath -and (Test-Path $binPath -ErrorAction SilentlyContinue)) {
            Get-FilePublisher -FilePath $binPath
        } elseif ($svc.PathName -match "^C:\\Windows\\") {
            "Windows System Service"
        } else {
            "Could not verify"
        }
        $isKnown   = Test-IsKnownPublisher -Publisher $publisher
        $isSuspPath= $false

        foreach ($sp in $SUSPICIOUS_PROC_PATHS) {
            if ($svc.PathName -like "*$sp*") { $isSuspPath = $true; break }
        }

        # Only include non-Microsoft services or suspicious ones
        if ($isKnown -and -not $isSuspPath) { continue }

        $serviceEntries += [PSCustomObject]@{
            "Service Name" = $svc.Name
            "Display Name" = $svc.DisplayName
            "State"        = $svc.State
            "Start Mode"   = $svc.StartMode
            "Path"         = $svc.PathName
            "Publisher"    = $publisher
            "Flag"         = if ($isSuspPath) { "?? Suspicious path" } elseif (-not $isKnown) { "Unknown publisher" } else { "" }
        }

        if ($isSuspPath) {
            $allFindings += New-Finding -Severity $SEV_RED `
                -Title "Service Running From Suspicious Location: $($svc.DisplayName)" `
                -Detail "Path: $($svc.PathName)" `
                -WhyItMatters "Legitimate Windows services run from System32 or Program Files. Services in Temp or AppData are a major red flag." `
                -WhyMightBeNormal "Extremely rare for legitimate software."
        }
    }
} catch {
    $serviceEntries = @()
}

$svcHtml = if ($serviceEntries.Count -gt 0) {
    "<p style='color:#64748b;font-size:0.82rem;margin-bottom:0.8rem'>Showing non-Microsoft services and any flagged services. System services are filtered.</p>"
    (ConvertTo-HtmlTable `
        -Data $serviceEntries `
        -Headers @("Service Name","Display Name","State","Start Mode","Path","Publisher","Flag") `
        -Properties @("Service Name","Display Name","State","Start Mode","Path","Publisher","Flag"))
} else {
    "<p class='no-findings'>? All running services are from known publishers or Windows system paths.</p>"
    $allFindings += New-Finding -Severity $SEV_GREEN `
        -Title "All Running Services From Known Publishers" `
        -Detail "No third-party or unknown-publisher services found running outside standard paths." `
        -WhyItMatters "Malicious services typically run from non-standard locations or with unsigned binaries."
}

$bodyHtml += ConvertTo-HtmlSection -Title "Non-System Services" -Content $svcHtml

# =============================================================================
# COLLECT: Boot Configuration
# =============================================================================
Write-Host "[*] Reading boot configuration..."

$bcdOutput = Invoke-Safe {
    $result = & bcdedit /enum all 2>&1
    $result -join "`n"
}

$bcdHtml = if ($bcdOutput) {
    $safeBcd = ConvertTo-SafeHtml($bcdOutput)
    "<pre style='font-family:monospace;font-size:0.78rem;color:#94a3b8;white-space:pre-wrap;max-height:400px;overflow-y:auto'>$safeBcd</pre>"
} else {
    "<p class='no-findings'>Could not retrieve boot configuration (requires Administrator).</p>"
}

# Check for safeboot forced (malware sometimes forces safe boot to disable AV)
$safeBoot = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Option" -Name "OptionValue"
if ($safeBoot) {
    $allFindings += New-Finding -Severity $SEV_RED `
        -Title "System Configured to Boot into Safe Mode" `
        -Detail "SafeBoot OptionValue = $safeBoot. The machine will boot into Safe Mode on next restart." `
        -WhyItMatters "Some ransomware and malware force Safe Mode boot to disable security software that doesn't run in Safe Mode." `
        -WhyMightBeNormal "User may have manually set this for troubleshooting. Should be cleared after troubleshooting is complete."
}

$bodyHtml += ConvertTo-HtmlSection -Title "Boot Configuration Data" -Content $bcdHtml -StartCollapsed $true

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
Write-Host "[+] Module 06 complete."
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
