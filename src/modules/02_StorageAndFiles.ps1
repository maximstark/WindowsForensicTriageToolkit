# =============================================================================
# Module 02 -- Storage & Files
# Windows Forensic Triage Toolkit
# =============================================================================
# What this module collects:
#   - Full partition map (all volumes including hidden/unnamed)
#   - BitLocker encryption status per volume
#   - Unallocated space detection
#   - Executables in suspicious locations (AppData, Temp, ProgramData, Public)
#   - Recently created executables system-wide (last 30 days)
#   - Contents of Temp directories (executables only)
#   - Prefetch file listing (what has run recently)
#   - PowerShell command history
#   - Recently modified files in sensitive paths
#   - Recycle Bin inspection
#
# Admin required: Partial (BitLocker status needs admin; rest works without)
# Typical runtime: 2-5 minutes (file scanning takes time)
# =============================================================================

#Requires -Version 5.1

# Encoding fix - ensures correct display on all Windows code pages
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
. "$ScriptDir\..\lib\Common.ps1"

$MODULE_NUM   = "02"
$MODULE_TITLE = "Storage & Files"
$SCAN_TIME    = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$HOSTNAME     = $env:COMPUTERNAME

Write-Host ""
Write-Host "============================================"
Write-Host " Module 02 -- Storage & Files"
Write-Host "============================================"
Write-Host ""

$reportDir  = Initialize-ReportDir -ModuleName $MODULE_TITLE
$reportFile = Join-Path $reportDir "02_StorageAndFiles.html"

$allFindings = @()
$bodyHtml    = ""

# =============================================================================
# COLLECT: Partition Map
# =============================================================================
Write-Host "[*] Mapping all partitions..."

$partitions = Invoke-Safe { Get-Partition -ErrorAction Stop }
$volumes    = Invoke-Safe { Get-Volume -ErrorAction Stop }

$partHtml = ""
if ($volumes) {
    $volRows = $volumes | ForEach-Object {
        $sizeGB  = if ($_.Size -gt 0) { [math]::Round($_.Size / 1GB, 2) } else { 0 }
        $freeGB  = if ($_.SizeRemaining -gt 0) { [math]::Round($_.SizeRemaining / 1GB, 2) } else { 0 }
        $freePct = if ($sizeGB -gt 0) { [math]::Round(($freeGB / $sizeGB) * 100, 1) } else { 0 }

        # Flag very small free space
        if ($sizeGB -gt 1 -and $freePct -lt 10) {
            $allFindings += New-Finding `
                -Severity $SEV_YELLOW `
                -Title "Low Disk Space on Volume $($_.DriveLetter): ($freePct% free)" `
                -Detail "Only $freeGB GB free of $sizeGB GB total." `
                -WhyItMatters "Attackers sometimes fill drives with data before exfiltration. Low space can also prevent update installation." `
                -WhyMightBeNormal "Simply a full drive from normal use."
        }

        [PSCustomObject]@{
            "Letter"      = if ($_.DriveLetter) { "$($_.DriveLetter):" } else { "(no letter)" }
            "Label"       = $_.FileSystemLabel
            "FileSystem"  = $_.FileSystem
            "Size (GB)"   = $sizeGB
            "Free (GB)"   = $freeGB
            "Free %"      = "$freePct%"
            "Health"      = $_.HealthStatus
            "Type"        = $_.DriveType
        }
    }
    $partHtml = ConvertTo-HtmlTable `
        -Data $volRows `
        -Headers @("Letter","Label","FileSystem","Size (GB)","Free (GB)","Free %","Health","Type") `
        -Properties @("Letter","Label","FileSystem","Size (GB)","Free (GB)","Free %","Health","Type")

    # Check for volumes with no drive letter (potential hidden volumes)
    $noLetter = $volumes | Where-Object { -not $_.DriveLetter -and $_.Size -gt 500MB }
    foreach ($v in $noLetter) {
        $sizeGB = [math]::Round($v.Size / 1GB, 2)
        if ($v.FileSystemLabel -notmatch "Recovery|EFI|System Reserved|WinRE") {
            $allFindings += New-Finding `
                -Severity $SEV_YELLOW `
                -Title "Large Volume With No Drive Letter ($sizeGB GB)" `
                -Detail "Label: '$($v.FileSystemLabel)'. FileSystem: $($v.FileSystem). Health: $($v.HealthStatus)." `
                -WhyItMatters "Hidden or unlettered volumes larger than expected system partitions can indicate a concealed data store." `
                -WhyMightBeNormal "Recovery, EFI, and WinRE partitions are always unlettered. This was flagged because the label doesn't match those names."
        }
    }
} else {
    $partHtml = "<p class='no-findings'>Could not retrieve volume data.</p>"
}

$bodyHtml += ConvertTo-HtmlSection -Title "Volume / Partition Map" -Content $partHtml

# =============================================================================
# COLLECT: BitLocker Status
# =============================================================================
Write-Host "[*] Checking BitLocker status..."

$bitlockerHtml = ""
try {
    $blVolumes = Get-BitLockerVolume -ErrorAction Stop
    $blRows = $blVolumes | ForEach-Object {
        [PSCustomObject]@{
            "Volume"             = $_.MountPoint
            "Protection Status"  = $_.ProtectionStatus
            "Encryption Status"  = $_.VolumeStatus
            "Encryption Method"  = $_.EncryptionMethod
            "Key Protectors"     = ($_.KeyProtector | ForEach-Object { $_.KeyProtectorType }) -join ", "
        }
    }
    $bitlockerHtml = ConvertTo-HtmlTable `
        -Data $blRows `
        -Headers @("Volume","Protection","Encryption","Method","Key Protectors") `
        -Properties @("Volume","Protection Status","Encryption Status","Encryption Method","Key Protectors")

    # Flag unprotected volumes that have data
    foreach ($bl in $blVolumes) {
        if ($bl.ProtectionStatus -eq "Off" -and $bl.MountPoint -eq "C:") {
            $allFindings += New-Finding `
                -Severity $SEV_YELLOW `
                -Title "BitLocker Not Active on System Drive ($($bl.MountPoint))" `
                -Detail "Protection status: $($bl.ProtectionStatus). Encryption: $($bl.VolumeStatus)." `
                -WhyItMatters "Without BitLocker, an attacker with physical access can read all data by booting from external media." `
                -WhyMightBeNormal "Many home users don't enable BitLocker. Not a sign of attack, but a security gap worth closing."
        }
    }
    
    $allFindings += New-Finding `
        -Severity $SEV_INFO `
        -Title "BitLocker Status Retrieved Successfully" `
        -Detail "$(($blVolumes | Where-Object {$_.ProtectionStatus -eq 'On'}).Count) of $($blVolumes.Count) volume(s) protected." `
        -WhyItMatters "BitLocker encrypts data at rest, protecting against physical theft."
        
} catch {
    $bitlockerHtml = "<p class='no-findings'>BitLocker query requires Administrator privileges. Run as admin for full results.</p>"
    $allFindings += New-Finding `
        -Severity $SEV_YELLOW `
        -Title "BitLocker Status Unavailable" `
        -Detail "Administrator privileges required to query BitLocker status." `
        -WhyItMatters "Run this module as Administrator for complete results."
}

$bodyHtml += ConvertTo-HtmlSection -Title "BitLocker Encryption Status" -Content $bitlockerHtml

# =============================================================================
# COLLECT: Executables in Suspicious Locations
# =============================================================================
Write-Host "[*] Scanning for executables in suspicious locations..."
Write-Host "    (This may take 1-2 minutes)"

$suspiciousExes = @()
$scanPaths = @(
    $env:TEMP,
    $env:LOCALAPPDATA + "\Temp",
    "C:\Windows\Temp",
    $env:APPDATA,
    "C:\ProgramData",
    $env:PUBLIC
)

foreach ($path in $scanPaths) {
    if (Test-Path $path -ErrorAction SilentlyContinue) {
        $exes = Get-ChildItem -Path $path -Include $EXECUTABLE_EXTENSIONS `
                              -Recurse -Force -ErrorAction SilentlyContinue |
                Where-Object {
                    -not $_.PSIsContainer -and
                    # v1.5: Skip files in whitelisted Microsoft/browser AppData paths
                    -not (Test-IsWhitelistedPath -FilePath $_.FullName)
                } |
                Select-Object -First 100  # Cap per directory to avoid runaway scan

        foreach ($exe in $exes) {
            $publisher = Get-FilePublisher -FilePath $exe.FullName
            $isKnown   = Test-IsKnownPublisher -Publisher $publisher
            $ageDays   = [math]::Round(((Get-Date) - $exe.CreationTime).TotalDays, 0)

            $suspiciousExes += [PSCustomObject]@{
                "File"        = $exe.Name
                "Location"    = $exe.DirectoryName
                "Size (KB)"   = [math]::Round($exe.Length / 1KB, 1)
                "Created"     = $exe.CreationTime.ToString("yyyy-MM-dd")
                "Modified"    = $exe.LastWriteTime.ToString("yyyy-MM-dd")
                "Publisher"   = $publisher
                "Known"       = if ($isKnown) { "Yes" } else { "UNKNOWN" }
            }

            if (-not $isKnown -and $publisher -ne "File not found") {
                $sev = if ($publisher -eq "UNSIGNED") { $SEV_RED } else { $SEV_YELLOW }
                $allFindings += New-Finding `
                    -Severity $sev `
                    -Title "$(if($publisher -eq 'UNSIGNED'){'Unsigned'} else {'Unknown publisher'}) executable in sensitive location: $($exe.Name)" `
                    -Detail "Path: $($exe.FullName) | Publisher: $publisher | Created: $($exe.CreationTime.ToString('yyyy-MM-dd'))" `
                    -WhyItMatters "Malware frequently installs to AppData/Temp because these locations don't require admin privileges to write to." `
                    -WhyMightBeNormal "Some legitimate software installs helpers or updaters to AppData. Check the file name against known software."
            }
        }
    }
}

$exeHtml = if ($suspiciousExes.Count -gt 0) {
    ConvertTo-HtmlTable `
        -Data $suspiciousExes `
        -Headers @("File","Location","Size (KB)","Created","Modified","Publisher","Known") `
        -Properties @("File","Location","Size (KB)","Created","Modified","Publisher","Known")
} else {
    "<p class='no-findings'>? No executables found in suspicious locations.</p>"
}

$bodyHtml += ConvertTo-HtmlSection -Title "Executables in Sensitive Locations" -Content $exeHtml

# =============================================================================
# COLLECT: Recently Created Executables (Last 30 Days)
# =============================================================================
Write-Host "[*] Scanning for recently created executables (last 30 days)..."
Write-Host "    (Scanning Program Files and Windows directories)"

$cutoff    = (Get-Date).AddDays(-30)
$scanRoots = @("C:\Program Files", "C:\Program Files (x86)", "C:\Windows\System32", "C:\Windows\SysWOW64")
$recentExes = @()

foreach ($root in $scanRoots) {
    if (Test-Path $root -ErrorAction SilentlyContinue) {
        $found = Get-ChildItem -Path $root -Include "*.exe" -Recurse -Force -ErrorAction SilentlyContinue |
                 Where-Object { $_.CreationTime -gt $cutoff -and -not $_.PSIsContainer } |
                 Select-Object -First 50

        foreach ($f in $found) {
            $publisher = Get-FilePublisher -FilePath $f.FullName
            $recentExes += [PSCustomObject]@{
                "File"      = $f.Name
                "Path"      = $f.DirectoryName
                "Created"   = $f.CreationTime.ToString("yyyy-MM-dd HH:mm")
                "Publisher" = $publisher
            }
        }
    }
}

$recentHtml = if ($recentExes.Count -gt 0) {
    ConvertTo-HtmlTable `
        -Data $recentExes `
        -Headers @("File","Path","Created","Publisher") `
        -Properties @("File","Path","Created","Publisher")
} else {
    "<p class='no-findings'>? No recently created executables found in system directories.</p>"
}

$bodyHtml += ConvertTo-HtmlSection -Title "Recently Created Executables (Last 30 Days)" -Content $recentHtml -StartCollapsed $true

# =============================================================================
# COLLECT: Prefetch Files (What Has Run Recently)
# =============================================================================
Write-Host "[*] Reading prefetch files..."

$prefetchPath = "C:\Windows\Prefetch"
$prefetchHtml = ""

if (Test-Path $prefetchPath -ErrorAction SilentlyContinue) {
    $pfFiles = Get-ChildItem -Path $prefetchPath -Filter "*.pf" -ErrorAction SilentlyContinue |
               Sort-Object LastWriteTime -Descending |
               Select-Object -First 75

    if ($pfFiles) {
        $pfRows = $pfFiles | ForEach-Object {
            $exeName = $_.Name -replace "-[A-F0-9]+\.pf$", ""
            [PSCustomObject]@{
                "Executable"   = $exeName
                "Last Run"     = $_.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
                "Prefetch File"= $_.Name
            }
        }
        $prefetchHtml = "<p style='color:#64748b;font-size:0.82rem;margin-bottom:0.8rem'>Showing last 75 executed programs (most recent first). Prefetch only exists if it has been run at least once.</p>"
        $prefetchHtml += ConvertTo-HtmlTable `
            -Data $pfRows `
            -Headers @("Executable","Last Run","Prefetch File") `
            -Properties @("Executable","Last Run","Prefetch File")

        # Flag anything that looks like a known RAT
        foreach ($pf in $pfRows) {
            foreach ($rat in $KNOWN_RAT_NAMES) {
                if ($pf.Executable -like "*$rat*") {
                    $allFindings += New-Finding `
                        -Severity $SEV_RED `
                        -Title "Known Remote Access Tool In Prefetch: $($pf.Executable)" `
                        -Detail "Last executed: $($pf.'Last Run'). This executable has run on this machine." `
                        -WhyItMatters "Prefetch records prove this program was executed. Even if now deleted, it ran." `
                        -WhyMightBeNormal "Some of these tools (TeamViewer, AnyDesk) are legitimately used for tech support."
                }
            }
        }
    } else {
        $prefetchHtml = "<p class='no-findings'>No prefetch files found.</p>"
    }
} else {
    $prefetchHtml = "<p class='no-findings'>Prefetch directory not accessible or prefetch is disabled on this system.</p>"
}

$bodyHtml += ConvertTo-HtmlSection -Title "Prefetch -- Recently Executed Programs" -Content $prefetchHtml -StartCollapsed $true

# =============================================================================
# COLLECT: PowerShell Command History
# =============================================================================
Write-Host "[*] Reading PowerShell command history..."

$histPath = Join-Path $env:APPDATA "Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
$psHistHtml = ""

if (Test-Path $histPath -ErrorAction SilentlyContinue) {
    $histLines = Get-Content -Path $histPath -ErrorAction SilentlyContinue
    if ($histLines -and $histLines.Count -gt 0) {
        # Look for suspicious patterns
        $suspiciousPatterns = @(
            @{ Pattern = "IEX|Invoke-Expression";          Reason = "Code execution from string -- common malware technique" },
            @{ Pattern = "DownloadString|DownloadFile";    Reason = "Downloading content from internet via PowerShell" },
            @{ Pattern = "EncodedCommand|-enc ";           Reason = "Base64 encoded command -- often used to hide malicious intent" },
            @{ Pattern = "Bypass|ExecutionPolicy";         Reason = "Attempting to bypass PowerShell security controls" },
            @{ Pattern = "New-Object Net.WebClient";       Reason = "Creating web client -- download cradle technique" },
            @{ Pattern = "Start-BitsTransfer";             Reason = "BITS transfer -- can be abused for stealthy downloads" },
            @{ Pattern = "Set-MpPreference.*Disable";      Reason = "Attempting to disable Windows Defender" },
            @{ Pattern = "netsh.*firewall";                Reason = "Modifying Windows Firewall rules" },
            @{ Pattern = "reg add.*Run";                   Reason = "Adding registry persistence key" },
            @{ Pattern = "schtasks.*create";               Reason = "Creating scheduled task -- persistence mechanism" }
        )

        foreach ($line in $histLines) {
            foreach ($sp in $suspiciousPatterns) {
                if ($line -match $sp.Pattern) {
                    # Task 3: Filter Set-ExecutionPolicy with -Scope Process -- only flag
                    # LocalMachine or CurrentUser scope changes, not session-only scope overrides
                    if ($sp.Pattern -match "Bypass\|ExecutionPolicy" -and $line -match "Set-ExecutionPolicy" -and $line -match "-Scope\s+Process") {
                        continue
                    }
                    $allFindings += New-Finding `
                        -Severity $SEV_RED `
                        -Title "Suspicious PowerShell Command In History" `
                        -Detail "Command: $line | Reason: $($sp.Reason)" `
                        -WhyItMatters "This command pattern is associated with malware, post-exploitation, or security control bypass." `
                        -WhyMightBeNormal "Security researchers and IT administrators legitimately use these commands. Context matters."
                }
            }
        }

        # Show last 50 commands
        $recent = $histLines | Select-Object -Last 50
        $psHistHtml = "<p style='color:#64748b;font-size:0.82rem;margin-bottom:0.8rem'>Showing last 50 commands. Full history: $($histLines.Count) commands.</p>"
        $psHistHtml += "<table><tbody>"
        $i = 0
        foreach ($line in ($recent | Sort-Object -Descending)) {
            $safe = ConvertTo-SafeHtml($line)
            $psHistHtml += "<tr><td style='color:#64748b;width:40px'>$i</td><td class='mono'>$safe</td></tr>"
            $i++
        }
        $psHistHtml += "</tbody></table>"
    } else {
        $psHistHtml = "<p class='no-findings'>PowerShell history file exists but is empty.</p>"
    }
} else {
    $psHistHtml = "<p class='no-findings'>No PowerShell history file found at expected location. PSReadLine may not be installed or history was cleared.</p>"
}

$bodyHtml += ConvertTo-HtmlSection -Title "PowerShell Command History" -Content $psHistHtml -StartCollapsed $true

# =============================================================================
# ASSEMBLE REPORT
# =============================================================================
Write-Host "[*] Writing report..."

$summaryHtml  = Get-SummaryBar -AllFindings $allFindings
$findingsHtml = ConvertTo-HtmlFindings -Findings $allFindings
$findingsSection = ConvertTo-HtmlSection -Title "Findings & Flags" -Content $findingsHtml

$fullHtml  = (Get-HtmlHeader -ModuleTitle $MODULE_TITLE -ModuleNumber $MODULE_NUM -Hostname $HOSTNAME -ScanTime $SCAN_TIME)
$fullHtml += $summaryHtml
$fullHtml += $findingsSection
$fullHtml += $bodyHtml
$fullHtml += Get-HtmlFooter

$fullHtml | Out-File -FilePath $reportFile -Encoding UTF8 -Force

Write-Host ""
Write-Host "[+] Module 02 complete."
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
