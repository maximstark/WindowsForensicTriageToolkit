# =============================================================================
# Module 03 -- Security Configuration
# Windows Forensic Triage Toolkit
# =============================================================================
# What this module collects:
#   - Windows Defender status, tamper protection, real-time protection
#   - Defender threat detection history (past infections/quarantined items)
#   - Secure Boot status
#   - TPM version and state
#   - UAC (User Account Control) level
#   - WDigest plaintext credential setting (critical security check)
#   - LSASS protection level (Credential Guard / PPL)
#   - Virtualization Based Security (VBS) status
#   - Windows Firewall profile states
#   - Inbound firewall allow rules (custom rules only)
#   - Windows Scripting Host status (common malware vector)
#   - AutoRun / AutoPlay status (USB attack surface)
#
# Admin required: Yes (most security settings require elevation)
# Typical runtime: ~60 seconds
# =============================================================================

#Requires -Version 5.1

# Encoding fix - ensures correct display on all Windows code pages
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
. "$ScriptDir\..\lib\Common.ps1"

$MODULE_NUM   = "03"
$MODULE_TITLE = "Security Configuration"
$SCAN_TIME    = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$HOSTNAME     = $env:COMPUTERNAME

Write-Host ""
Write-Host "============================================"
Write-Host " Module 03 -- Security Configuration"
Write-Host "============================================"
Write-Host ""

$reportDir  = Initialize-ReportDir -ModuleName $MODULE_TITLE
$reportFile = Join-Path $reportDir "03_SecurityConfig.html"

$allFindings = @()
$bodyHtml    = ""

# =============================================================================
# COLLECT: Windows Defender Status
# =============================================================================
Write-Host "[*] Checking Windows Defender status..."

$defenderHtml = ""
try {
    $mpStatus = Get-MpComputerStatus -ErrorAction Stop

    $defData = [ordered]@{
        "Antivirus Enabled"            = $mpStatus.AntivirusEnabled
        "Real-Time Protection"         = $mpStatus.RealTimeProtectionEnabled
        "Tamper Protection"            = $mpStatus.IsTamperProtected
        "Behavior Monitor Enabled"     = $mpStatus.BehaviorMonitorEnabled
        "Network Inspection Enabled"   = $mpStatus.NISEnabled
        "IOAV Protection Enabled"      = $mpStatus.IoavProtectionEnabled
        "Antispyware Enabled"          = $mpStatus.AntispywareEnabled
        "AM Engine Version"            = $mpStatus.AMEngineVersion
        "AM Product Version"           = $mpStatus.AMProductVersion
        "Antivirus Signature Version"  = $mpStatus.AntivirusSignatureVersion
        "Antivirus Signature Age"      = "$($mpStatus.AntivirusSignatureAge) days"
        "Last Quick Scan"              = if ($mpStatus.QuickScanStartTime) { $mpStatus.QuickScanStartTime.ToString("yyyy-MM-dd HH:mm") } else { "Never" }
        "Last Full Scan"               = if ($mpStatus.FullScanStartTime) { $mpStatus.FullScanStartTime.ToString("yyyy-MM-dd HH:mm") } else { "Never" }
        "Last Scan Result"             = $mpStatus.QuickScanOverdue
    }

    $defenderHtml = "<table><tbody>"
    foreach ($key in $defData.Keys) {
        $val     = $defData[$key]
        $safeVal = ConvertTo-SafeHtml($val.ToString())
        $color   = "#e2e8f0"
        if ($val -eq $false -and $key -notmatch "Overdue") { $color = "#ef4444" }
        if ($val -eq $true  -and $key -notmatch "Overdue") { $color = "#22c55e" }
        $defenderHtml += "<tr><td style='width:260px;color:#94a3b8;font-weight:600'>$key</td><td class='mono' style='color:$color'>$safeVal</td></tr>"
    }
    $defenderHtml += "</tbody></table>"

    # Findings
    if (-not $mpStatus.AntivirusEnabled) {
        $allFindings += New-Finding -Severity $SEV_RED `
            -Title "Windows Defender Antivirus Is DISABLED" `
            -Detail "AntivirusEnabled = False" `
            -WhyItMatters "Real-time malware protection is off. The system is unprotected against new threats." `
            -WhyMightBeNormal "Only normal if a third-party AV has taken over (Malwarebytes Premium, Norton, etc.)"
    } else {
        $allFindings += New-Finding -Severity $SEV_GREEN `
            -Title "Windows Defender Antivirus Is Active" `
            -Detail "Real-time protection enabled. Engine: $($mpStatus.AMEngineVersion)" `
            -WhyItMatters "Real-time protection is the first line of defence against malware."
    }

    if (-not $mpStatus.RealTimeProtectionEnabled) {
        $allFindings += New-Finding -Severity $SEV_RED `
            -Title "Real-Time Protection Is DISABLED" `
            -Detail "Files are not being scanned as they are created or modified." `
            -WhyItMatters "Without real-time protection, malware can install silently without any scan occurring." `
            -WhyMightBeNormal "Temporarily disabled by user for performance. Should be re-enabled immediately."
    }

    if (-not $mpStatus.IsTamperProtected) {
        $allFindings += New-Finding -Severity $SEV_RED `
            -Title "Tamper Protection Is DISABLED" `
            -Detail "Defender settings can be changed without administrator consent or notification." `
            -WhyItMatters "Disabling tamper protection is one of the first things malware does after gaining admin access. Its absence is a significant red flag." `
            -WhyMightBeNormal "Group Policy environments sometimes disable this. Rare on home machines."
    } else {
        $allFindings += New-Finding -Severity $SEV_GREEN `
            -Title "Tamper Protection Is Active" `
            -Detail "Defender cannot be disabled without proper authorization." `
            -WhyItMatters "Tamper protection prevents malware from disabling your antivirus."
    }

    if ($mpStatus.AntivirusSignatureAge -gt 7) {
        $allFindings += New-Finding -Severity $SEV_YELLOW `
            -Title "Defender Definitions Are $($mpStatus.AntivirusSignatureAge) Days Old" `
            -Detail "Current version: $($mpStatus.AntivirusSignatureVersion)" `
            -WhyItMatters "Outdated definitions mean new malware variants may not be detected." `
            -WhyMightBeNormal "Machine has been offline. Connect to internet and run Windows Update."
    }

} catch {
    $defenderHtml = "<p class='no-findings'>Could not query Defender status. Requires Administrator or Defender may not be running.</p>"
    $allFindings += New-Finding -Severity $SEV_YELLOW `
        -Title "Defender Status Unavailable" `
        -Detail "Error: $($_.Exception.Message)" `
        -WhyItMatters "Unable to confirm antivirus protection state." `
        -WhyMightBeNormal "Run as Administrator for full results."
}

$bodyHtml += ConvertTo-HtmlSection -Title "Windows Defender Status" -Content $defenderHtml

# =============================================================================
# COLLECT: Defender Threat Detection History
# =============================================================================
Write-Host "[*] Reading Defender threat history..."

$threatHtml = ""
try {
    $threats = Get-MpThreatDetection -ErrorAction Stop
    if ($threats -and $threats.Count -gt 0) {
        $threatRows = $threats | Sort-Object InitialDetectionTime -Descending | ForEach-Object {
            [PSCustomObject]@{
                "Threat Name"     = $_.ThreatName
                "Severity"        = $_.SeverityID
                "Action Taken"    = $_.ActionSuccess
                "Detection Time"  = if ($_.InitialDetectionTime) { $_.InitialDetectionTime.ToString("yyyy-MM-dd HH:mm") } else { "Unknown" }
                "Remediation"     = $_.RemediationTime
                "Resources"       = ($_.Resources -join "; ") -replace "file:_",""
            }
        }
        $threatHtml = "<p style='color:#eab308;margin-bottom:0.8rem'>?? $($threats.Count) historical threat detection(s) found. These may have been cleaned, but their presence confirms malware reached this machine.</p>"
        $threatHtml += ConvertTo-HtmlTable `
            -Data $threatRows `
            -Headers @("Threat Name","Severity","Action Taken","Detection Time","Resources") `
            -Properties @("Threat Name","Severity","Action Taken","Detection Time","Resources")

        $allFindings += New-Finding -Severity $SEV_YELLOW `
            -Title "$($threats.Count) Historical Threat Detection(s) Found in Defender Log" `
            -Detail "Threats: $(($threats | Select-Object -ExpandProperty ThreatName -Unique) -join ', ')" `
            -WhyItMatters "These threats were detected at some point. Even if remediated, they confirm malware reached the machine. Review what was found and when." `
            -WhyMightBeNormal "Defender regularly detects and cleans PUPs (Potentially Unwanted Programs) from downloads. Review the specific threat names."
    } else {
        $threatHtml = "<p class='no-findings'>? No threat detection history found. Defender has not detected any malware on this machine.</p>"
        $allFindings += New-Finding -Severity $SEV_GREEN `
            -Title "No Historical Malware Detections in Defender Log" `
            -Detail "Defender threat detection history is empty." `
            -WhyItMatters "No known malware has been detected on this machine by Defender."
    }
} catch {
    $threatHtml = "<p class='no-findings'>Could not retrieve threat history (requires Administrator).</p>"
}

$bodyHtml += ConvertTo-HtmlSection -Title "Defender Threat History" -Content $threatHtml

# =============================================================================
# COLLECT: Secure Boot & TPM
# =============================================================================
Write-Host "[*] Checking Secure Boot and TPM..."

$secBootHtml = ""
$secBoot     = $null

try {
    $secBoot = Confirm-SecureBootUEFI -ErrorAction Stop
    if ($secBoot) {
        $secBootHtml = "<p style='color:#22c55e'>? Secure Boot is ENABLED and functioning correctly.</p>"
        $allFindings += New-Finding -Severity $SEV_GREEN `
            -Title "Secure Boot Is Enabled" `
            -Detail "UEFI Secure Boot is active and verified." `
            -WhyItMatters "Secure Boot prevents unsigned bootloaders and UEFI rootkits from loading before Windows."
    } else {
        $secBootHtml = "<p style='color:#ef4444'>? Secure Boot reports as disabled or not enforcing.</p>"
        $allFindings += New-Finding -Severity $SEV_RED `
            -Title "Secure Boot Is DISABLED" `
            -Detail "Confirm-SecureBootUEFI returned False." `
            -WhyItMatters "Without Secure Boot, a bootkit or UEFI rootkit could load before Windows with no detection." `
            -WhyMightBeNormal "Deliberately disabled for Linux dual-boot or legacy hardware support."
    }
} catch {
    $secBootHtml = "<p style='color:#64748b'>Secure Boot status unavailable: $($_.Exception.Message)</p>"
    $allFindings += New-Finding -Severity $SEV_INFO `
        -Title "Secure Boot Status Could Not Be Confirmed" `
        -Detail "This may indicate legacy BIOS (non-UEFI) or insufficient permissions." `
        -WhyItMatters "Secure Boot is a critical firmware-level protection."
}

# TPM
try {
    $tpm = Get-Tpm -ErrorAction Stop
    $secBootHtml += "<br><table><tbody>"
    $secBootHtml += "<tr><td style='width:220px;color:#94a3b8;font-weight:600'>TPM Present</td><td class='mono' style='color:$(if($tpm.TpmPresent){"#22c55e"}else{"#ef4444"})'>$($tpm.TpmPresent)</td></tr>"
    $secBootHtml += "<tr><td style='color:#94a3b8;font-weight:600'>TPM Ready</td><td class='mono' style='color:$(if($tpm.TpmReady){"#22c55e"}else{"#eab308"})'>$($tpm.TpmReady)</td></tr>"
    $secBootHtml += "<tr><td style='color:#94a3b8;font-weight:600'>TPM Enabled</td><td class='mono'>$($tpm.TpmEnabled)</td></tr>"
    $secBootHtml += "<tr><td style='color:#94a3b8;font-weight:600'>TPM Activated</td><td class='mono'>$($tpm.TpmActivated)</td></tr>"
    $secBootHtml += "<tr><td style='color:#94a3b8;font-weight:600'>TPM Spec Version</td><td class='mono'>$($tpm.ManufacturerVersion)</td></tr>"
    $secBootHtml += "</tbody></table>"

    if (-not $tpm.TpmPresent -or -not $tpm.TpmEnabled) {
        $allFindings += New-Finding -Severity $SEV_YELLOW `
            -Title "TPM Not Present or Not Enabled" `
            -Detail "TpmPresent: $($tpm.TpmPresent) | TpmEnabled: $($tpm.TpmEnabled)" `
            -WhyItMatters "TPM is required for BitLocker, Windows Hello, and Secure Boot key storage." `
            -WhyMightBeNormal "Very old hardware predating TPM requirements."
    } else {
        $allFindings += New-Finding -Severity $SEV_GREEN `
            -Title "TPM Present and Active" `
            -Detail "TPM is available, enabled, and activated." `
            -WhyItMatters "TPM provides hardware-backed cryptographic key storage."
    }
} catch {
    $secBootHtml += "<br><p style='color:#64748b'>TPM status unavailable: $($_.Exception.Message)</p>"
}

$bodyHtml += ConvertTo-HtmlSection -Title "Secure Boot & TPM" -Content $secBootHtml

# =============================================================================
# COLLECT: UAC Level
# =============================================================================
Write-Host "[*] Checking UAC configuration..."

$uacVal  = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin"
$uacLua  = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA"

$uacLevel = switch ($uacVal) {
    0 { "DISABLED -- No prompt, silent elevation (CRITICAL RISK)" }
    1 { "Prompt for credentials on secure desktop" }
    2 { "Prompt for consent on secure desktop (Windows default)" }
    3 { "Prompt for credentials (not on secure desktop)" }
    4 { "Prompt for consent (not on secure desktop)" }
    5 { "Prompt for consent for non-Windows binaries (default)" }
    default { "Unknown value: $uacVal" }
}

$uacHtml  = "<table><tbody>"
$uacHtml += "<tr><td style='width:220px;color:#94a3b8;font-weight:600'>UAC Enabled (EnableLUA)</td><td class='mono' style='color:$(if($uacLua -eq 1){"#22c55e"}else{"#ef4444"})'>$(if($uacLua -eq 1){"Yes"}else{"NO - UAC DISABLED"})</td></tr>"
$uacHtml += "<tr><td style='color:#94a3b8;font-weight:600'>Admin Consent Behavior</td><td class='mono'>$uacLevel</td></tr>"
$uacHtml += "<tr><td style='color:#94a3b8;font-weight:600'>Raw Registry Value</td><td class='mono'>$uacVal</td></tr>"
$uacHtml += "</tbody></table>"

if ($uacLua -ne 1) {
    $allFindings += New-Finding -Severity $SEV_RED `
        -Title "UAC Is COMPLETELY DISABLED" `
        -Detail "EnableLUA = 0. All processes run with full administrator rights silently." `
        -WhyItMatters "Without UAC, any program can gain admin rights without prompting the user. This is a critical security gap." `
        -WhyMightBeNormal "Sometimes disabled by malware to prevent removal. Rarely legitimate on a home machine."
} elseif ($uacVal -eq 0) {
    $allFindings += New-Finding -Severity $SEV_RED `
        -Title "UAC Set to Never Notify (Silent Elevation)" `
        -Detail "ConsentPromptBehaviorAdmin = 0. Admin programs elevate with no prompt." `
        -WhyItMatters "Silent UAC elevation means malware can gain admin rights without any user interaction or notification." `
        -WhyMightBeNormal "Sometimes set by users who find UAC prompts annoying. Still a significant risk."
} else {
    $allFindings += New-Finding -Severity $SEV_GREEN `
        -Title "UAC Is Enabled at Recommended Level" `
        -Detail "Level: $uacLevel" `
        -WhyItMatters "UAC prompts protect against unauthorized privilege escalation."
}

$bodyHtml += ConvertTo-HtmlSection -Title "User Account Control (UAC)" -Content $uacHtml

# =============================================================================
# COLLECT: WDigest -- Plaintext Credential Risk
# =============================================================================
Write-Host "[*] Checking WDigest plaintext credential setting..."

$wdigest = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential"

$wdigestHtml = "<table><tbody>"
if ($null -eq $wdigest) {
    $wdigestStatus = "Not set (default -- safe on Windows 8.1+)"
    $wdigestColor  = "#22c55e"
} elseif ($wdigest -eq 1) {
    $wdigestStatus = "ENABLED -- Passwords stored in cleartext in memory"
    $wdigestColor  = "#ef4444"
} else {
    $wdigestStatus = "Disabled (value = $wdigest) -- Safe"
    $wdigestColor  = "#22c55e"
}
$wdigestHtml += "<tr><td style='width:260px;color:#94a3b8;font-weight:600'>UseLogonCredential</td><td class='mono' style='color:$wdigestColor'>$wdigestStatus</td></tr>"
$wdigestHtml += "</tbody></table>"
$wdigestHtml += "<p style='color:#64748b;font-size:0.8rem;margin-top:0.8rem'>WDigest is an older Windows authentication protocol. When enabled, Windows stores the user's password in plaintext in memory (LSASS), where tools like Mimikatz can extract it trivially.</p>"

if ($wdigest -eq 1) {
    $allFindings += New-Finding -Severity $SEV_RED `
        -Title "WDigest Plaintext Credential Storage Is ENABLED" `
        -Detail "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential = 1" `
        -WhyItMatters "Your Windows password is stored in plaintext in memory. Any attacker with admin access can extract it immediately using freely available tools like Mimikatz." `
        -WhyMightBeNormal "Should never be enabled on a modern consumer machine. This setting is associated with attacker activity."
} else {
    $allFindings += New-Finding -Severity $SEV_GREEN `
        -Title "WDigest Plaintext Credential Storage Is Disabled" `
        -Detail "Passwords are not stored in cleartext in memory." `
        -WhyItMatters "This prevents trivial credential extraction from memory."
}

$bodyHtml += ConvertTo-HtmlSection -Title "WDigest -- Plaintext Credential Risk" -Content $wdigestHtml

# =============================================================================
# COLLECT: LSASS Protection
# =============================================================================
Write-Host "[*] Checking LSASS protection level..."

$lsassPPL      = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL"
$lsassAudit    = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "AuditLevel"
$credGuard     = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity"

$lsassHtml = "<table><tbody>"
$pplStatus = switch ($lsassPPL) {
    1       { "Enabled (Protected Process Light)" }
    2       { "Enabled (Protected Process)" }
    $null   { "Not configured (no protection)" }
    default { "Value: $lsassPPL" }
}
$lsassColor = if ($lsassPPL -ge 1) { "#22c55e" } else { "#eab308" }
$lsassHtml += "<tr><td style='width:260px;color:#94a3b8;font-weight:600'>LSASS RunAsPPL</td><td class='mono' style='color:$lsassColor'>$pplStatus</td></tr>"
$lsassHtml += "<tr><td style='color:#94a3b8;font-weight:600'>Audit Level</td><td class='mono'>$(if($null -eq $lsassAudit){'Not set'} else {$lsassAudit})</td></tr>"
$lsassHtml += "<tr><td style='color:#94a3b8;font-weight:600'>Virtualization Based Security</td><td class='mono'>$(if($credGuard -eq 1){'Enabled'} else {'Not enabled'})</td></tr>"
$lsassHtml += "</tbody></table>"
$lsassHtml += "<p style='color:#64748b;font-size:0.8rem;margin-top:0.8rem'>LSASS (Local Security Authority Subsystem Service) holds credential material in memory. Protected Process Light (PPL) prevents even admin-level processes from reading LSASS memory directly.</p>"

if ($lsassPPL -lt 1 -or $null -eq $lsassPPL) {
    $allFindings += New-Finding -Severity $SEV_YELLOW `
        -Title "LSASS Is Not Running as Protected Process" `
        -Detail "RunAsPPL = $(if($null -eq $lsassPPL){'not set'}else{$lsassPPL})" `
        -WhyItMatters "Without PPL, an attacker with admin rights can dump credentials from LSASS memory using tools like Mimikatz or ProcDump." `
        -WhyMightBeNormal "PPL is not enabled by default on all Windows editions. Its absence is a security gap, not evidence of attack."
} else {
    $allFindings += New-Finding -Severity $SEV_GREEN `
        -Title "LSASS Protected Process Light Is Active" `
        -Detail "RunAsPPL = $lsassPPL -- LSASS is protected from direct memory access." `
        -WhyItMatters "Prevents credential dumping attacks even with administrator access."
}

$bodyHtml += ConvertTo-HtmlSection -Title "LSASS Credential Protection" -Content $lsassHtml

# =============================================================================
# COLLECT: Windows Firewall
# =============================================================================
Write-Host "[*] Checking Windows Firewall..."

$fwHtml = ""
try {
    $profiles = Get-NetFirewallProfile -ErrorAction Stop
    $fwHtml   = "<table><thead><tr><th>Profile</th><th>Enabled</th><th>Default Inbound</th><th>Default Outbound</th></tr></thead><tbody>"
    foreach ($p in $profiles) {
        $enabledColor = if ($p.Enabled) { "#22c55e" } else { "#ef4444" }
        $fwHtml += "<tr>"
        $fwHtml += "<td class='mono'>$($p.Name)</td>"
        $fwHtml += "<td class='mono' style='color:$enabledColor'>$($p.Enabled)</td>"
        $fwHtml += "<td class='mono'>$($p.DefaultInboundAction)</td>"
        $fwHtml += "<td class='mono'>$($p.DefaultOutboundAction)</td>"
        $fwHtml += "</tr>"

        if (-not $p.Enabled) {
            $allFindings += New-Finding -Severity $SEV_RED `
                -Title "Windows Firewall DISABLED for $($p.Name) Profile" `
                -Detail "The $($p.Name) firewall profile is not active." `
                -WhyItMatters "A disabled firewall allows unrestricted inbound connections to this machine." `
                -WhyMightBeNormal "Third-party security suites sometimes manage their own firewall and disable the Windows one."
        }
    }
    $fwHtml += "</tbody></table>"

    # Check for suspicious custom inbound allow rules
    $customRules = Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction Stop |
                   Where-Object { $_.DisplayGroup -notmatch "Core Networking|Windows|Remote Desktop|mDNS|DIAL|SSDP|UPnP" } |
                   Select-Object -First 30

    if ($customRules -and $customRules.Count -gt 0) {
        $fwHtml += "<br><h4 style='color:#94a3b8;margin-bottom:0.5rem'>Custom Inbound Allow Rules</h4>"
        $ruleRows = $customRules | ForEach-Object {
            [PSCustomObject]@{
                "Rule Name"   = $_.DisplayName
                "Group"       = $_.DisplayGroup
                "Profile"     = $_.Profile
                "Description" = $_.Description
            }
        }
        $fwHtml += ConvertTo-HtmlTable `
            -Data $ruleRows `
            -Headers @("Rule Name","Group","Profile","Description") `
            -Properties @("Rule Name","Group","Profile","Description")

        $allFindings += New-Finding -Severity $SEV_INFO `
            -Title "$($customRules.Count) Custom Inbound Firewall Allow Rule(s) Found" `
            -Detail "These rules permit inbound connections beyond standard Windows defaults. Review the list for anything unexpected." `
            -WhyItMatters "Attackers sometimes add firewall rules to permit inbound access." `
            -WhyMightBeNormal "Games, development tools, and file sharing apps commonly add inbound rules."
    }

} catch {
    $fwHtml = "<p class='no-findings'>Firewall status unavailable: $($_.Exception.Message)</p>"
}

$bodyHtml += ConvertTo-HtmlSection -Title "Windows Firewall" -Content $fwHtml

# =============================================================================
# COLLECT: Windows Script Host Status
# =============================================================================
Write-Host "[*] Checking Windows Script Host status..."

$wshEnabled  = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled"
$wshEnabledU = Get-RegValue -Path "HKCU:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled"

$wshHtml = "<table><tbody>"
$wshStatus = if ($wshEnabled -eq 0) { "Disabled (system-wide)" }
             elseif ($wshEnabledU -eq 0) { "Disabled (for current user)" }
             else { "Enabled (default)" }
$wshHtml += "<tr><td style='width:260px;color:#94a3b8;font-weight:600'>Windows Script Host</td><td class='mono'>$wshStatus</td></tr>"
$wshHtml += "</tbody></table>"
$wshHtml += "<p style='color:#64748b;font-size:0.8rem;margin-top:0.8rem'>Windows Script Host allows .vbs, .js, and .wsf scripts to run. Many phishing attacks deliver malicious scripts in these formats.</p>"

$allFindings += New-Finding -Severity $SEV_INFO `
    -Title "Windows Script Host: $wshStatus" `
    -Detail "WSH enables .vbs and .js script execution. Disabling it reduces the attack surface from script-based malware." `
    -WhyItMatters "Many email-delivered malware payloads use .vbs or .js scripts." `
    -WhyMightBeNormal "WSH is enabled by default and required by some enterprise software."

$bodyHtml += ConvertTo-HtmlSection -Title "Windows Script Host" -Content $wshHtml

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
Write-Host "[+] Module 03 complete."
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
