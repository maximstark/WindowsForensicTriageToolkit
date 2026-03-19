# =============================================================================
# Module 04 -- Accounts & Authentication
# Windows Forensic Triage Toolkit
# =============================================================================
# What this module collects:
#   - All local user accounts with last logon, password age, status
#   - Members of the Administrators group (backdoor account detection)
#   - Recent successful logins (Event ID 4624) -- filtered for suspicious types
#   - Remote/RDP login events (Logon Type 10) -- should be zero on home machines
#   - Network logon events (Logon Type 3)
#   - Failed login attempts (Event ID 4625) -- brute force detection
#   - Account lockout events (Event ID 4740)
#   - Special privilege assignment (Event ID 4672)
#   - RDP connection history from registry (machines connected TO and FROM)
#   - Cached credentials count
#
# Admin required: Yes (Security event log requires elevation)
# Typical runtime: ~90 seconds (event log queries can be slow)
# =============================================================================

#Requires -Version 5.1

# Encoding fix - ensures correct display on all Windows code pages
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
. "$ScriptDir\..\lib\Common.ps1"

$MODULE_NUM   = "04"
$MODULE_TITLE = "Accounts & Authentication"
$SCAN_TIME    = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$HOSTNAME     = $env:COMPUTERNAME

Write-Host ""
Write-Host "============================================"
Write-Host " Module 04 -- Accounts & Authentication"
Write-Host "============================================"
Write-Host ""

$reportDir  = Initialize-ReportDir -ModuleName $MODULE_TITLE
$reportFile = Join-Path $reportDir "04_AccountsAndAuth.html"

$allFindings = @()
$bodyHtml    = ""

# Expected built-in account names -- anything else is suspicious
$EXPECTED_ACCOUNTS = @(
    "Administrator","DefaultAccount","Guest","WDAGUtilityAccount",
    "HomeGroupUser$","defaultuser0"
)

# =============================================================================
# COLLECT: Local User Accounts
# =============================================================================
Write-Host "[*] Enumerating local user accounts..."

$userHtml = ""
try {
    $users = Get-LocalUser -ErrorAction Stop

    $userRows = $users | ForEach-Object {
        # Task 5: Distinguish between never-logged-in and Microsoft accounts (no local LastLogon)
        $lastLogon = if ($_.LastLogon) {
            $_.LastLogon.ToString("yyyy-MM-dd HH:mm")
        } else {
            $profilePath = Join-Path "C:\Users" $_.Name
            if (Test-Path $profilePath -ErrorAction SilentlyContinue) {
                "Unavailable (Microsoft account)"
            } else {
                "Never logged in"
            }
        }
        $pwAge     = if ($_.PasswordLastSet) {
            "$([math]::Round(((Get-Date) - $_.PasswordLastSet).TotalDays, 0)) days ago"
        } else { "Never set" }

        [PSCustomObject]@{
            "Username"       = $_.Name
            "Full Name"      = $_.FullName
            "Enabled"        = $_.Enabled
            "Last Logon"     = $lastLogon
            "Password Set"   = $pwAge
            "Password Exp."  = $_.PasswordExpires
            "Description"    = $_.Description
        }
    }

    $userHtml = ConvertTo-HtmlTable `
        -Data $userRows `
        -Headers @("Username","Full Name","Enabled","Last Logon","Password Set","Password Exp.","Description") `
        -Properties @("Username","Full Name","Enabled","Last Logon","Password Set","Password Exp.","Description")

    # Flag unexpected enabled accounts
    foreach ($u in $users) {
        $isExpected = $EXPECTED_ACCOUNTS -contains $u.Name
        $isCurrentUser = $u.Name -eq $env:USERNAME

        if ($u.Enabled -and -not $isExpected -and -not $isCurrentUser) {
            # Task 5: Use the corrected LastLogon display from $userRows lookup or recompute
            $lastLogonDisplay = if ($u.LastLogon) {
                $u.LastLogon.ToString("yyyy-MM-dd")
            } else {
                $profilePath = Join-Path "C:\Users" $u.Name
                if (Test-Path $profilePath -ErrorAction SilentlyContinue) { "Unavailable (Microsoft account)" } else { "Never logged in" }
            }
            # Task 7: Expose SID as a dedicated structured field
            $userSid = if ($u.SID) { $u.SID.Value } else { "" }
            $allFindings += New-Finding -Severity $SEV_INFO `
                -Title "Active User Account: $($u.Name)" `
                -Detail "Enabled: $($u.Enabled) | Last logon: $lastLogonDisplay" `
                -WhyItMatters "Verify this account is expected. Backdoor accounts are often created with innocuous-looking names." `
                -WhyMightBeNormal "This is likely the primary user account. Confirm the name matches the machine owner." `
                -Sid $userSid
        }

        # Guest account being enabled is a red flag
        if ($u.Name -eq "Guest" -and $u.Enabled) {
            $guestSid = if ($u.SID) { $u.SID.Value } else { "" }
            $allFindings += New-Finding -Severity $SEV_RED `
                -Title "Guest Account Is ENABLED" `
                -Detail "The built-in Guest account is active. It has no password by default." `
                -WhyItMatters "An enabled Guest account provides unauthenticated local access to the machine." `
                -WhyMightBeNormal "Almost never intentional on a personal machine." `
                -Sid $guestSid
        }
    }

    $allFindings += New-Finding -Severity $SEV_INFO `
        -Title "$($users.Count) Local User Account(s) Found" `
        -Detail "Enabled: $(($users | Where-Object {$_.Enabled}).Count) | Disabled: $(($users | Where-Object {-not $_.Enabled}).Count)" `
        -WhyItMatters "Unexpected accounts can be attacker-created backdoors."

} catch {
    $userHtml = "<p class='no-findings'>Could not enumerate local users: $($_.Exception.Message)</p>"
}

$bodyHtml += ConvertTo-HtmlSection -Title "Local User Accounts" -Content $userHtml

# =============================================================================
# COLLECT: Administrators Group Members
# =============================================================================
Write-Host "[*] Checking Administrators group membership..."

$adminHtml = ""
try {
    $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop

    $adminRows = $admins | ForEach-Object {
        [PSCustomObject]@{
            "Name"        = $_.Name
            "Object Type" = $_.ObjectClass
            "PrincipalSource" = $_.PrincipalSource
        }
    }
    $adminHtml = ConvertTo-HtmlTable `
        -Data $adminRows `
        -Headers @("Name","Type","Source") `
        -Properties @("Name","Object Type","PrincipalSource")

    # More than 2 admins on a home machine is unusual
    if ($admins.Count -gt 2) {
        $allFindings += New-Finding -Severity $SEV_YELLOW `
            -Title "$($admins.Count) Accounts in Administrators Group" `
            -Detail "Members: $(($admins | Select-Object -ExpandProperty Name) -join ', ')" `
            -WhyItMatters "Attackers frequently add their backdoor account to the Administrators group for persistent elevated access." `
            -WhyMightBeNormal "Family computers with multiple admin users, or domain-joined machines with domain admin groups."
    } else {
        $allFindings += New-Finding -Severity $SEV_GREEN `
            -Title "$($admins.Count) Administrator Account(s) -- Expected Count" `
            -Detail "Members: $(($admins | Select-Object -ExpandProperty Name) -join ', ')" `
            -WhyItMatters "Administrator count is within normal range for a personal machine."
    }

} catch {
    $adminHtml = "<p class='no-findings'>Could not query Administrators group: $($_.Exception.Message)</p>"
}

$bodyHtml += ConvertTo-HtmlSection -Title "Administrators Group Members" -Content $adminHtml

# =============================================================================
# COLLECT: Recent Logon Events
# =============================================================================
Write-Host "[*] Reading logon events (last 30 days)..."
Write-Host "    (This may take 30-60 seconds)"

# Logon type reference:
# 2  = Interactive (local login)
# 3  = Network (SMB, mapped drives)
# 4  = Batch
# 5  = Service
# 7  = Unlock
# 8  = NetworkCleartext
# 9  = NewCredentials
# 10 = RemoteInteractive (RDP) <- most suspicious on home machine
# 11 = CachedInteractive

$suspiciousLogonTypes = @(3, 8, 9, 10)

$logonHtml = ""
try {
    $logonEvents = Get-SafeEventLog -LogName "Security" -EventId 4624 -MaxEvents 200

    if ($logonEvents.Count -gt 0) {
        $logonRows = @()
        foreach ($evt in $logonEvents) {
            try {
                $xml      = [xml]$evt.ToXml()
                $ns       = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
                $ns.AddNamespace("e", "http://schemas.microsoft.com/win/2004/08/events/event")

                $logonType  = $xml.SelectSingleNode("//e:Data[@Name='LogonType']", $ns).'#text'
                $subjectUser= $xml.SelectSingleNode("//e:Data[@Name='SubjectUserName']", $ns).'#text'
                $targetUser = $xml.SelectSingleNode("//e:Data[@Name='TargetUserName']", $ns).'#text'
                $sourceIP   = $xml.SelectSingleNode("//e:Data[@Name='IpAddress']", $ns).'#text'
                $logonProc  = $xml.SelectSingleNode("//e:Data[@Name='LogonProcessName']", $ns).'#text'

                # Skip machine accounts and system noise
                if ($targetUser -match "\$$" -or $targetUser -eq "SYSTEM" -or $targetUser -eq "LOCAL SERVICE" -or $targetUser -eq "NETWORK SERVICE") { continue }

                $typeName = switch ($logonType) {
                    "2"  { "Interactive" }
                    "3"  { "Network" }
                    "4"  { "Batch" }
                    "5"  { "Service" }
                    "7"  { "Unlock" }
                    "8"  { "NetworkCleartext" }
                    "9"  { "NewCredentials" }
                    "10" { "RDP/RemoteInteractive" }
                    "11" { "CachedInteractive" }
                    default { "Type $logonType" }
                }

                $isSuspicious = $suspiciousLogonTypes -contains [int]$logonType

                $logonRows += [PSCustomObject]@{
                    "Time"      = $evt.TimeCreated.ToString("yyyy-MM-dd HH:mm")
                    "User"      = $targetUser
                    "Type"      = $typeName
                    "Source IP" = if ($sourceIP -and $sourceIP -ne "-" -and $sourceIP -ne "::1" -and $sourceIP -ne "127.0.0.1") { $sourceIP } else { "Local" }
                    "Process"   = $logonProc.Trim()
                    "Flag"      = if ($isSuspicious) { "?? REVIEW" } else { "" }
                }

                # Immediate flag for RDP logons
                if ($logonType -eq "10") {
                    $allFindings += New-Finding -Severity $SEV_RED `
                        -Title "RDP Login Detected: $targetUser from $sourceIP" `
                        -Detail "Time: $($evt.TimeCreated.ToString('yyyy-MM-dd HH:mm')) | Source: $sourceIP" `
                        -WhyItMatters "Remote Desktop logins should not occur on a home machine unless deliberately configured. This indicates someone connected remotely." `
                        -WhyMightBeNormal "User or IT support may have used RDP intentionally for remote assistance."
                }

                # Network logon from non-local IP
                if ($logonType -eq "3" -and $sourceIP -and $sourceIP -notmatch "^(127\.|::1|-)") {
                    $allFindings += New-Finding -Severity $SEV_YELLOW `
                        -Title "Network Logon from External IP: $sourceIP" `
                        -Detail "User: $targetUser | Time: $($evt.TimeCreated.ToString('yyyy-MM-dd HH:mm'))" `
                        -WhyItMatters "Network logons from non-local addresses can indicate unauthorized remote access attempts." `
                        -WhyMightBeNormal "Can occur with mapped network drives or domain authentication."
                }
            } catch { continue }
        }

        if ($logonRows.Count -gt 0) {
            $logonHtml = "<p style='color:#64748b;font-size:0.82rem;margin-bottom:0.8rem'>Showing up to 200 non-system logon events from last 30 days. RDP and Network logons are flagged for review.</p>"
            $logonHtml += ConvertTo-HtmlTable `
                -Data ($logonRows | Select-Object -First 100) `
                -Headers @("Time","User","Type","Source IP","Process","Flag") `
                -Properties @("Time","User","Type","Source IP","Process","Flag")
        } else {
            $logonHtml = "<p class='no-findings'>? No non-system logon events found in last 30 days.</p>"
        }
    } else {
        $logonHtml = "<p class='no-findings'>No logon events found. Security log may be cleared or access denied.</p>"
        $allFindings += New-Finding -Severity $SEV_YELLOW `
            -Title "Security Event Log Has No Logon Events" `
            -Detail "Either log was cleared, logging is disabled, or admin access is required." `
            -WhyItMatters "Attackers sometimes clear event logs to remove evidence of access." `
            -WhyMightBeNormal "Log simply rolled over on a machine with limited log size configured."
    }
} catch {
    $logonHtml = "<p class='no-findings'>Could not read Security event log: $($_.Exception.Message). Run as Administrator.</p>"
}

$bodyHtml += ConvertTo-HtmlSection -Title "Logon Events (Last 30 Days)" -Content $logonHtml

# =============================================================================
# COLLECT: Failed Login Attempts (Brute Force Detection)
# =============================================================================
Write-Host "[*] Checking for failed login attempts..."

$failedHtml = ""
try {
    $failedEvents = Get-SafeEventLog -LogName "Security" -EventId 4625 -MaxEvents 100

    if ($failedEvents.Count -gt 0) {
        $failedRows = @()
        foreach ($evt in $failedEvents) {
            try {
                $xml = [xml]$evt.ToXml()
                $ns  = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
                $ns.AddNamespace("e", "http://schemas.microsoft.com/win/2004/08/events/event")

                $targetUser = $xml.SelectSingleNode("//e:Data[@Name='TargetUserName']", $ns).'#text'
                $sourceIP   = $xml.SelectSingleNode("//e:Data[@Name='IpAddress']", $ns).'#text'
                $failReason = $xml.SelectSingleNode("//e:Data[@Name='SubStatus']", $ns).'#text'

                if ($targetUser -match "\$$" -or $targetUser -eq "-") { continue }

                $failedRows += [PSCustomObject]@{
                    "Time"       = $evt.TimeCreated.ToString("yyyy-MM-dd HH:mm")
                    "User"       = $targetUser
                    "Source IP"  = if ($sourceIP -and $sourceIP -ne "-") { $sourceIP } else { "Local" }
                    "SubStatus"  = $failReason
                }
            } catch { continue }
        }

        if ($failedRows.Count -ge 10) {
            $allFindings += New-Finding -Severity $SEV_RED `
                -Title "$($failedRows.Count)+ Failed Login Attempts Detected" `
                -Detail "High number of failures may indicate brute force attack. Review source IPs and usernames." `
                -WhyItMatters "Repeated failed logins from the same IP or against the same account indicate an active attack attempt." `
                -WhyMightBeNormal "User repeatedly mistyping their own password. Check if failures cluster around one time period."
        } elseif ($failedRows.Count -gt 0) {
            $allFindings += New-Finding -Severity $SEV_YELLOW `
                -Title "$($failedRows.Count) Failed Login Attempt(s) Found" `
                -Detail "Review the list for patterns suggesting unauthorized access attempts." `
                -WhyItMatters "Even a small number of failures from unknown sources is worth reviewing." `
                -WhyMightBeNormal "Users occasionally mistype passwords."
        }

        if ($failedRows.Count -gt 0) {
            $failedHtml = ConvertTo-HtmlTable `
                -Data $failedRows `
                -Headers @("Time","User","Source IP","SubStatus") `
                -Properties @("Time","User","Source IP","SubStatus")
        } else {
            $failedHtml = "<p class='no-findings'>? No failed login events found in last 30 days.</p>"
        }
    } else {
        $failedHtml = "<p class='no-findings'>? No failed login events found.</p>"
    }
} catch {
    $failedHtml = "<p class='no-findings'>Could not read failed login events: $($_.Exception.Message)</p>"
}

$bodyHtml += ConvertTo-HtmlSection -Title "Failed Login Attempts" -Content $failedHtml

# =============================================================================
# COLLECT: RDP Connection History (Registry)
# =============================================================================
Write-Host "[*] Reading RDP connection history from registry..."

$rdpHtml  = ""
$rdpPaths = @(
    "HKCU:\SOFTWARE\Microsoft\Terminal Server Client\Default",
    "HKCU:\SOFTWARE\Microsoft\Terminal Server Client\Servers"
)

$rdpEntries = @()

# MRU list (recently connected TO)
try {
    $mruKeys = Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Terminal Server Client\Default" -ErrorAction Stop
    $mruKeys.PSObject.Properties | Where-Object { $_.Name -like "MRU*" } | ForEach-Object {
        $rdpEntries += [PSCustomObject]@{
            "Direction" = "Outbound (connected to)"
            "Host"      = $_.Value
            "Source"    = "MRU List"
        }
    }
} catch {}

# Saved server entries
try {
    $servers = Get-ChildItem -Path "HKCU:\SOFTWARE\Microsoft\Terminal Server Client\Servers" -ErrorAction Stop
    foreach ($s in $servers) {
        $rdpEntries += [PSCustomObject]@{
            "Direction" = "Outbound (saved server)"
            "Host"      = $s.PSChildName
            "Source"    = "Saved Servers"
        }
    }
} catch {}

if ($rdpEntries.Count -gt 0) {
    $rdpHtml = "<p style='color:#64748b;font-size:0.82rem;margin-bottom:0.8rem'>These are remote machines this computer has connected TO via RDP. This is normal for IT support or remote work.</p>"
    $rdpHtml += ConvertTo-HtmlTable `
        -Data $rdpEntries `
        -Headers @("Direction","Host","Source") `
        -Properties @("Direction","Host","Source")

    $allFindings += New-Finding -Severity $SEV_INFO `
        -Title "$($rdpEntries.Count) RDP Connection History Entries Found" `
        -Detail "Hosts: $(($rdpEntries | Select-Object -ExpandProperty Host) -join ', ')" `
        -WhyItMatters "Shows which machines this device has connected to via Remote Desktop." `
        -WhyMightBeNormal "Normal for IT workers, remote work, or tech support sessions."
} else {
    $rdpHtml = "<p class='no-findings'>? No RDP connection history found in registry.</p>"
    $allFindings += New-Finding -Severity $SEV_GREEN `
        -Title "No RDP Connection History" `
        -Detail "This machine has no saved RDP connections in the registry." `
        -WhyItMatters "Absence of RDP history is expected on a personal machine not used for remote work."
}

$bodyHtml += ConvertTo-HtmlSection -Title "RDP Connection History" -Content $rdpHtml

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
Write-Host "[+] Module 04 complete."
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
