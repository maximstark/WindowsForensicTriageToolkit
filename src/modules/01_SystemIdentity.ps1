# =============================================================================
# Module 01 -- System Identity
# Windows Forensic Triage Toolkit
# =============================================================================
# What this module collects:
#   - Hardware model, serial number, UUID
#   - BIOS vendor and version (cross-referenceable with manufacturer)
#   - CPU, RAM, OS version and build
#   - Windows install date and last boot time
#   - PowerShell version
#   - Timezone (relevant for correlating event log timestamps)
#   - Drive overview (physical drives only -- partitions in Module 02)
#
# Admin required: No (all WMI queries available to standard users)
# Typical runtime: 15-30 seconds
# =============================================================================

#Requires -Version 5.1

# Encoding fix - ensures correct display on all Windows code pages
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

# Load shared library
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
. "$ScriptDir\..\lib\Common.ps1"

$MODULE_NUM   = "01"
$MODULE_TITLE = "System Identity"
$SCAN_TIME    = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$HOSTNAME     = $env:COMPUTERNAME

Write-Host ""
Write-Host "============================================"
Write-Host " Module 01 -- System Identity"
Write-Host "============================================"
Write-Host ""

# Initialize output directory
$reportDir  = Initialize-ReportDir -ModuleName $MODULE_TITLE
$reportFile = Join-Path $reportDir "01_SystemIdentity.html"

$allFindings = @()
$bodyHtml    = ""

# =============================================================================
# COLLECT: Hardware Information
# =============================================================================
Write-Host "[*] Collecting hardware information..."

$cs = Invoke-Safe { Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop }
$bs = Invoke-Safe { Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop }
$os = Invoke-Safe { Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop }
$cpu= Invoke-Safe { Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Select-Object -First 1 }

$hwData = [ordered]@{
    "Computer Name"        = $env:COMPUTERNAME
    "Manufacturer"         = if ($cs) { $cs.Manufacturer } else { "Unknown" }
    "Model"                = if ($cs) { $cs.Model } else { "Unknown" }
    "System Family"        = Invoke-Safe { (Get-CimInstance Win32_ComputerSystemProduct).Version } ?? "Unknown"
    "Serial Number"        = if ($bs) { $bs.SerialNumber } else { "Unknown" }
    "UUID"                 = Invoke-Safe { (Get-CimInstance Win32_ComputerSystemProduct).UUID } ?? "Unknown"
    "System Board"         = Invoke-Safe { (Get-CimInstance Win32_BaseBoard).Product } ?? "Unknown"
    "BIOS Vendor"          = if ($bs) { $bs.Manufacturer } else { "Unknown" }
    "BIOS Version"         = if ($bs) { $bs.SMBIOSBIOSVersion } else { "Unknown" }
    "BIOS Release Date"    = if ($bs) { $bs.ReleaseDate.ToString("yyyy-MM-dd") } else { "Unknown" }
    "CPU"                  = if ($cpu) { $cpu.Name.Trim() } else { "Unknown" }
    "CPU Cores (Physical)" = if ($cpu) { $cpu.NumberOfCores } else { "Unknown" }
    "CPU Threads (Logical)"= if ($cpu) { $cpu.NumberOfLogicalProcessors } else { "Unknown" }
    "Total RAM"            = if ($cs) { "$([math]::Round($cs.TotalPhysicalMemory / 1GB, 1)) GB" } else { "Unknown" }
}

# Build hardware table HTML
$hwHtml = "<table><tbody>"
foreach ($key in $hwData.Keys) {
    $val     = $hwData[$key]
    $safeVal = ConvertTo-SafeHtml($val.ToString())
    $hwHtml += "<tr><td style='width:220px;color:#94a3b8;font-weight:600'>$key</td><td class='mono'>$safeVal</td></tr>"
}
$hwHtml += "</tbody></table>"
$bodyHtml += ConvertTo-HtmlSection -Title "Hardware" -Content $hwHtml

# =============================================================================
# COLLECT: Operating System
# =============================================================================
Write-Host "[*] Collecting OS information..."

$installDate = if ($os) {
    try { $os.InstallDate.ToString("yyyy-MM-dd HH:mm:ss") } catch { "Unknown" }
} else { "Unknown" }

$lastBoot = if ($os) {
    try { $os.LastBootUpTime.ToString("yyyy-MM-dd HH:mm:ss") } catch { "Unknown" }
} else { "Unknown" }

$uptimeSpan = if ($os) {
    try {
        $span = (Get-Date) - $os.LastBootUpTime
        "$($span.Days)d $($span.Hours)h $($span.Minutes)m"
    } catch { "Unknown" }
} else { "Unknown" }

$psVersion = "$($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor)"
$timezone  = Invoke-Safe { (Get-TimeZone).DisplayName } ?? "Unknown"

$osData = [ordered]@{
    "OS Name"              = if ($os) { $os.Caption } else { "Unknown" }
    "Version"              = if ($os) { $os.Version } else { "Unknown" }
    "Build Number"         = if ($os) { $os.BuildNumber } else { "Unknown" }
    "Architecture"         = if ($os) { $os.OSArchitecture } else { "Unknown" }
    "Edition"              = Invoke-Safe {
                                (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").EditionID
                             } ?? "Unknown"
    "Release ID / Version" = Invoke-Safe {
                                $reg = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
                                $disp = $reg.DisplayVersion
                                if ($disp) { $disp } else { $reg.ReleaseId }
                             } ?? "Unknown"
    "Install Date"         = $installDate
    "Last Boot"            = $lastBoot
    "Uptime"               = $uptimeSpan
    "System Drive"         = if ($os) { $os.SystemDrive } else { "Unknown" }
    "Windows Directory"    = if ($os) { $os.WindowsDirectory } else { "Unknown" }
    "Registered Owner"     = Invoke-Safe {
                                (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").RegisteredOwner
                             } ?? "Unknown"
    "PowerShell Version"   = $psVersion
    "Timezone"             = $timezone
}

$osHtml = "<table><tbody>"
foreach ($key in $osData.Keys) {
    $val     = $osData[$key]
    $safeVal = ConvertTo-SafeHtml($val.ToString())
    $osHtml += "<tr><td style='width:220px;color:#94a3b8;font-weight:600'>$key</td><td class='mono'>$safeVal</td></tr>"
}
$osHtml += "</tbody></table>"
$bodyHtml += ConvertTo-HtmlSection -Title "Operating System" -Content $osHtml

# =============================================================================
# COLLECT: Physical Drives Overview
# =============================================================================
Write-Host "[*] Collecting drive information..."

$drives = Invoke-Safe { Get-PhysicalDisk -ErrorAction Stop }

$driveHtml = ""
if ($drives) {
    $driveRows = $drives | ForEach-Object {
        [PSCustomObject]@{
            "Index"       = $_.DeviceId
            "Model"       = $_.FriendlyName
            "Bus"         = $_.BusType
            "Media Type"  = $_.MediaType
            "Size (GB)"   = [math]::Round($_.Size / 1GB, 1)
            "Health"      = $_.HealthStatus
            "Usage"       = $_.Usage
        }
    }
    $driveHtml = ConvertTo-HtmlTable `
        -Data $driveRows `
        -Headers @("Index","Model","Bus","Media Type","Size (GB)","Health","Usage") `
        -Properties @("Index","Model","Bus","Media Type","Size (GB)","Health","Usage")

    # Flag drives in unhealthy state
    foreach ($d in $drives) {
        if ($d.HealthStatus -ne "Healthy") {
            $allFindings += New-Finding `
                -Severity $SEV_RED `
                -Title "Drive Health Warning: $($d.FriendlyName)" `
                -Detail "Health status reported as: $($d.HealthStatus)" `
                -WhyItMatters "An unhealthy drive can indicate hardware failure or tampering. Back up data immediately." `
                -WhyMightBeNormal "Occasionally a transient WMI reporting error -- verify with manufacturer diagnostic tool."
        }
    }
} else {
    $driveHtml = "<p class='no-findings'>Could not retrieve physical disk data (may require admin).</p>"
}

$bodyHtml += ConvertTo-HtmlSection -Title "Physical Drives" -Content $driveHtml

# =============================================================================
# COLLECT: Environment Snapshot
# =============================================================================
Write-Host "[*] Collecting environment variables..."

$importantEnvVars = @(
    "COMPUTERNAME","USERNAME","USERDOMAIN","USERPROFILE",
    "APPDATA","LOCALAPPDATA","TEMP","TMP",
    "SYSTEMROOT","PROGRAMFILES","PROGRAMFILES(X86)","PROGRAMDATA",
    "PATH","PROCESSOR_ARCHITECTURE","NUMBER_OF_PROCESSORS"
)

$envHtml = "<table><thead><tr><th>Variable</th><th>Value</th></tr></thead><tbody>"
foreach ($var in $importantEnvVars) {
    $val = [System.Environment]::GetEnvironmentVariable($var)
    if ($null -ne $val) {
        $safeVal = ConvertTo-SafeHtml($val)
        $envHtml += "<tr><td class='mono' style='color:#94a3b8'>$var</td><td class='mono'>$safeVal</td></tr>"
    }
}
$envHtml += "</tbody></table>"
$bodyHtml += ConvertTo-HtmlSection -Title "Environment Variables" -Content $envHtml -StartCollapsed $true

# =============================================================================
# FINDINGS: BIOS Version Alert
# =============================================================================
Write-Host "[*] Evaluating findings..."

# Note: We can't auto-check against HP's latest -- flag for manual verification
if ($bs) {
    $allFindings += New-Finding `
        -Severity $SEV_INFO `
        -Title "BIOS Version: $($bs.SMBIOSBIOSVersion) -- Manual Verification Required" `
        -Detail "Vendor: $($bs.Manufacturer). Date: $($bs.ReleaseDate.ToString('yyyy-MM-dd')). Cannot automatically verify against manufacturer latest." `
        -WhyItMatters "Outdated BIOS can contain unpatched vulnerabilities. An unexpected BIOS version may indicate firmware tampering." `
        -WhyMightBeNormal "Most home users never update BIOS and run older versions without issue."
}

# Flag if system uptime is very long (machine never reboots -- some malware prevents reboots to maintain persistence)
if ($os) {
    try {
        $days = ((Get-Date) - $os.LastBootUpTime).Days
        if ($days -gt 30) {
            $allFindings += New-Finding `
                -Severity $SEV_YELLOW `
                -Title "System Has Been Running For $days Days Without Reboot" `
                -Detail "Last boot: $lastBoot" `
                -WhyItMatters "Some malware prevents or delays reboots to maintain in-memory persistence. Updates also require reboots to fully apply." `
                -WhyMightBeNormal "Many users simply don't reboot often. Not suspicious on its own."
        }
    } catch {}
}

# Flag if PowerShell version is old
$psMajor = $PSVersionTable.PSVersion.Major
if ($psMajor -lt 5) {
    $allFindings += New-Finding `
        -Severity $SEV_YELLOW `
        -Title "PowerShell Version $psVersion Is Outdated" `
        -Detail "PowerShell 5.1 is the minimum recommended version. Older versions lack Script Block Logging and other security features." `
        -WhyItMatters "Old PowerShell versions have fewer security controls and logging capabilities, making them easier for attackers to abuse." `
        -WhyMightBeNormal "Only found on very old Windows installations."
}

# =============================================================================
# ASSEMBLE AND WRITE REPORT
# =============================================================================
Write-Host "[*] Writing report..."

$summaryHtml = Get-SummaryBar -AllFindings $allFindings
$findingsHtml = ConvertTo-HtmlFindings -Findings $allFindings
$findingsSection = ConvertTo-HtmlSection -Title "Findings & Flags" -Content $findingsHtml

$fullHtml = (Get-HtmlHeader -ModuleTitle $MODULE_TITLE -ModuleNumber $MODULE_NUM -Hostname $HOSTNAME -ScanTime $SCAN_TIME)
$fullHtml += $summaryHtml
$fullHtml += $findingsSection
$fullHtml += $bodyHtml
$fullHtml += Get-HtmlFooter

$fullHtml | Out-File -FilePath $reportFile -Encoding UTF8 -Force

Write-Host ""
Write-Host "[+] Module 01 complete."
Write-Host "    Report saved to: $reportFile"
Write-Host ""

# Return findings count for launcher summary

# v1.5: Write JSON output for GUI report viewer
Write-ModuleJson -ReportDir $reportDir -ModuleNumber $MODULE_NUM -ModuleTitle $MODULE_TITLE `
    -Findings $allFindings -Hostname $HOSTNAME -ScanTime $SCAN_TIME

return @{
    Module   = $MODULE_TITLE
    Red      = ($allFindings | Where-Object { $_.Severity -eq "RED"    }).Count
    Yellow   = ($allFindings | Where-Object { $_.Severity -eq "YELLOW" }).Count
    Report   = $reportFile
}
