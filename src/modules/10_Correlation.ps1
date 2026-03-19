# =============================================================================
# Module 10 -- Cross-Module Correlation
# Windows Forensic Triage Toolkit
# =============================================================================
# What this module does:
#   - Reads all 9 JSON output files from the scan report directory
#   - Applies 7 cross-module correlation patterns to find relationships
#     between findings that no single module can detect on its own
#   - Produces three output categories:
#       Correlated Concerns  -- new escalated findings from cross-module analysis
#       Explained Findings   -- findings accounted for by normal software activity
#       Clean Correlations   -- positive security posture confirmations
#   - Outputs a noise-adjusted score table showing raw vs. explained counts
#
# Admin required: No (reads existing JSON output files only)
# Typical runtime: ~10 seconds
# =============================================================================

#Requires -Version 5.1

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
. "$ScriptDir\..\lib\Common.ps1"

$MODULE_NUM   = "10"
$MODULE_TITLE = "Cross-Module Correlation"
$SCAN_TIME    = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$HOSTNAME     = $env:COMPUTERNAME

Write-Host ""
Write-Host "============================================"
Write-Host " Module 10 -- Cross-Module Correlation"
Write-Host "============================================"
Write-Host ""

$reportDir  = Initialize-ReportDir -ModuleName $MODULE_TITLE
$reportFile = Join-Path $reportDir "10_Correlation.html"

$allFindings       = @()   # findings this module generates (for JSON/summary bar)
$correlatedConcerns  = @()
$explainedFindings   = @()
$cleanCorrelations   = @()

# =============================================================================
# LOAD: Read all module JSON files
# =============================================================================
Write-Host "[*] Loading module JSON output files..."

$moduleData = @{}
$jsonFiles  = Get-ChildItem -Path $reportDir -Filter "*.json" -ErrorAction SilentlyContinue |
              Where-Object { $_.Name -match '^0[1-9]_' } |
              Sort-Object Name

foreach ($jf in $jsonFiles) {
    try {
        $raw    = Get-Content -Path $jf.FullName -Raw -ErrorAction SilentlyContinue
        $parsed = $raw | ConvertFrom-Json
        $num    = $parsed.module
        if ($num) { $moduleData[$num] = $parsed }
        Write-Host "  [OK] Loaded module $num ($($jf.Name))"
    } catch {
        Write-Host "  [WARN] Could not parse $($jf.Name): $($_.Exception.Message)"
    }
}

# Helper: safe access to module findings array
function Get-ModuleFindings {
    param([string]$ModuleNum)
    if ($moduleData.ContainsKey($ModuleNum) -and $moduleData[$ModuleNum].findings) {
        return @($moduleData[$ModuleNum].findings)
    }
    return @()
}

# Helper: fuzzy name match (one name contains the other, stripped of punctuation)
function Test-FuzzyNameMatch {
    param([string]$A, [string]$B)
    if ([string]::IsNullOrWhiteSpace($A) -or [string]::IsNullOrWhiteSpace($B)) { return $false }
    $a2 = ($A.ToLower() -replace '[^a-z0-9]', '')
    $b2 = ($B.ToLower() -replace '[^a-z0-9]', '')
    if ($a2.Length -lt 3 -or $b2.Length -lt 3) { return $false }
    return ($a2 -like "*$b2*" -or $b2 -like "*$a2*")
}

# Helper: try to parse a date string, return $null on failure
function Try-ParseDate {
    param([string]$DateStr)
    if ([string]::IsNullOrWhiteSpace($DateStr)) { return $null }
    try { return [datetime]::Parse($DateStr.Trim()) } catch { return $null }
}

# Extract a named field from a pipe-delimited detail string: "Key: val | Key2: val2"
function Extract-DetailField {
    param([string]$Detail, [string]$Field)
    if ($Detail -match "$Field\s*:\s*([^|]+)") { return $Matches[1].Trim() }
    return ""
}

$mod03findings = Get-ModuleFindings "03"
$mod04findings = Get-ModuleFindings "04"
$mod05findings = Get-ModuleFindings "05"
$mod06findings = Get-ModuleFindings "06"
$mod08findings = Get-ModuleFindings "08"
$mod09findings = Get-ModuleFindings "09"

Write-Host ""
Write-Host "[*] Applying correlation patterns..."

# =============================================================================
# PATTERN 1: Scheduled task running under dormant account
# =============================================================================
Write-Host "  [1/7] Scheduled task under dormant account..."

# Build account lookup from Module 04
$accountLookup = @{}  # username.lower -> finding
foreach ($f04 in $mod04findings) {
    if ($f04.title -match '^Active User Account:\s*(.+)$') {
        $uname = $Matches[1].Trim()
        $accountLookup[$uname.ToLower()] = $f04
    }
}

# Evaluate task findings from Module 06
foreach ($f06 in $mod06findings) {
    if ($f06.title -notmatch 'Scheduled Task:') { continue }

    $taskName    = if ($f06.title -match 'Scheduled Task:\s*(.+)$') { $Matches[1].Trim() } else { $f06.title }
    $principalId = Extract-DetailField -Detail $f06.detail -Field 'Principal'
    if ([string]::IsNullOrWhiteSpace($principalId)) { continue }

    # Strip domain prefix if present (DOMAIN\user or just user)
    $principalShort = ($principalId -split '\\')[-1].Trim().ToLower()

    # Skip well-known system accounts
    if ($principalShort -match '^(system|localservice|networkservice|s-1-5-)') { continue }

    $acctFinding = $accountLookup[$principalShort]

    if ($acctFinding) {
        $acctDetail  = $acctFinding.detail
        $lastLogon   = Extract-DetailField -Detail $acctDetail -Field 'Last logon'
        $isDormant   = ($lastLogon -match 'Never|Unavailable')

        if ($isDormant) {
            # Check if account is also disabled
            $isDisabled = ($acctDetail -match 'Enabled:\s*False')
            $sev        = if ($isDisabled) { $SEV_RED } else { $SEV_YELLOW }
            $correlatedConcerns += New-Finding -Severity $sev `
                -Title "Correlated Concern: Task '$taskName' runs under dormant account '$principalId'" `
                -Detail "Task has no recorded interactive logon for its principal account. Sources: Module 06 (task), Module 04 (account). Last logon: $lastLogon$(if($isDisabled){' | Account is DISABLED'})" `
                -WhyItMatters "A scheduled task running under an account that has never logged in interactively may indicate a service account being abused as a persistence vehicle." `
                -WhyMightBeNormal "Service accounts legitimately run scheduled tasks and may never have an interactive logon."
        } else {
            $explainedFindings += New-Finding -Severity $SEV_INFO `
                -Title "Explained: Task '$taskName' runs under account '$principalId'" `
                -Detail "Account has recorded logon activity. Last logon: $lastLogon. Sources: Module 06 (task), Module 04 (account)." `
                -WhyItMatters "Task principal account shows normal interactive usage — no dormancy concern."
        }
    }
}

# =============================================================================
# PATTERN 2: Persistence entry with no matching software install
# =============================================================================
Write-Host "  [2/7] Persistence vs. software install cross-reference..."

# Collect all software names from Module 05 findings
$softwareFindings = @()
foreach ($f05 in $mod05findings) {
    if ($f05.title -match 'Recently Installed Software:\s*(.+)$') {
        $swName    = $Matches[1].Trim()
        $swDate    = Extract-DetailField -Detail $f05.detail -Field 'Install date'
        $softwareFindings += [PSCustomObject]@{ Name = $swName; Date = $swDate }
    }
}

# Track which persistence findings have been explained (used in Pattern 4)
$explainedPersistenceKeys = @{}

foreach ($f06 in $mod06findings) {
    if ($f06.title -notmatch 'Run Key|Unknown Publisher in Run Key') { continue }
    $entryName   = if ($f06.title -match ':\s*(.+)$') { $Matches[1].Trim() } else { $f06.title }
    $createdDate = $f06.createdDate
    $entryDate   = Try-ParseDate -DateStr $createdDate

    # Only flag entries older than 90 days with no matching software
    if ($entryDate -and $entryDate -gt (Get-Date).AddDays(-90)) { continue }

    $matched = $false
    foreach ($sw in $softwareFindings) {
        if (Test-FuzzyNameMatch -A $entryName -B $sw.Name) {
            if ($entryDate -and $sw.Date) {
                $swDate = Try-ParseDate -DateStr $sw.Date
                if ($swDate -and [Math]::Abs(($entryDate - $swDate).TotalDays) -le 7) {
                    $explainedPersistenceKeys[$entryName] = $true
                    $explainedFindings += New-Finding -Severity $SEV_INFO `
                        -Title "Explained: Run key '$entryName' corresponds to '$($sw.Name)' installed on $($sw.Date)" `
                        -Detail "Install date and run key creation are within 7 days. Sources: Module 06 (run key), Module 05 (software)." `
                        -WhyItMatters "Persistence entry creation aligns with a known software installation — expected behaviour."
                    $matched = $true
                    break
                }
            } else {
                # Name matches but no date available -- partial explanation
                $explainedPersistenceKeys[$entryName] = $true
                $explainedFindings += New-Finding -Severity $SEV_INFO `
                    -Title "Explained: Run key '$entryName' name matches installed software '$($sw.Name)'" `
                    -Detail "Name fuzzy-match found. Sources: Module 06 (run key), Module 05 (software)." `
                    -WhyItMatters "Run key name is consistent with a known installed application."
                $matched = $true
                break
            }
        }
    }

    if (-not $matched) {
        $correlatedConcerns += New-Finding -Severity $SEV_RED `
            -Title "Correlated Concern: Run key '$entryName' has no corresponding installation record (>90 days old)" `
            -Detail "No installed software found matching this run key entry. Created: $(if($createdDate){$createdDate}else{'unknown'}). Sources: Module 06 (run key), Module 05 (software)." `
            -WhyItMatters "An old persistence entry with no matching installed software is a significant indicator of a leftover malware foothold." `
            -WhyMightBeNormal "Software may have been uninstalled without cleaning its registry entry."
    }
}

# =============================================================================
# PATTERN 3: Network connection explained by installed software
# =============================================================================
Write-Host "  [3/7] Network connections vs. installed software..."

foreach ($f08 in $mod08findings) {
    if ($f08.title -notmatch 'Connection to Unidentified IP|Connection to Suspicious Port') { continue }

    $procName = Extract-DetailField -Detail $f08.detail -Field 'Process(?:es)?'
    if ([string]::IsNullOrWhiteSpace($procName)) { continue }

    # Check if already explained by vendor map (Task 8 appended text)
    if ($f08.detail -match 'Process is recognized') {
        # Find the software in Module 05
        $swMatch = $null
        foreach ($sw in $softwareFindings) {
            if (Test-FuzzyNameMatch -A $procName -B $sw.Name) { $swMatch = $sw; break }
        }
        if ($swMatch) {
            $explainedFindings += New-Finding -Severity $SEV_INFO `
                -Title "Explained: Connection by '$procName' is consistent with '$($swMatch.Name)' installed on $($swMatch.Date)" `
                -Detail "Process is a recognized vendor application with a matching installation record. Sources: Module 08 (network), Module 05 (software)." `
                -WhyItMatters "Outbound connection matches a known installed application — no further action required."
        } else {
            # Recognized vendor but no install record in Module 05
            $correlatedConcerns += New-Finding -Severity $SEV_YELLOW `
                -Title "Correlated Concern: '$procName' is making outbound connections but has no corresponding installation record" `
                -Detail "Process is in the vendor map but does not appear in the installed software list. Sources: Module 08 (network), Module 05 (software)." `
                -WhyItMatters "A recognized vendor process without a matching installation entry may indicate a portable/extracted copy or a partially installed application." `
                -WhyMightBeNormal "Some applications do not register in the standard uninstall registry (e.g. portable apps, Microsoft Store apps)."
        }
    } else {
        # Unrecognized process -- check Module 05 for a software match
        $swMatch = $null
        foreach ($sw in $softwareFindings) {
            if (Test-FuzzyNameMatch -A $procName -B $sw.Name) { $swMatch = $sw; break }
        }
        if ($swMatch) {
            $explainedFindings += New-Finding -Severity $SEV_INFO `
                -Title "Explained: Connection by '$procName' corresponds to '$($swMatch.Name)' installed on $($swMatch.Date)" `
                -Detail "Network connection process name fuzzy-matches a recently installed application. Sources: Module 08 (network), Module 05 (software)." `
                -WhyItMatters "Outbound connection is consistent with a known software installation."
        }
        # If no match, leave Module 08 finding unchanged (no new concern)
    }
}

# =============================================================================
# PATTERN 4: Recent software install with matching new persistence entry
# =============================================================================
Write-Host "  [4/7] Recent installs vs. new persistence entries..."

foreach ($sw in $softwareFindings) {
    $swDate = Try-ParseDate -DateStr $sw.Date
    if (-not $swDate) { continue }

    foreach ($f06 in $mod06findings) {
        if ($f06.title -notmatch 'Run Key') { continue }
        $entryName = if ($f06.title -match ':\s*(.+)$') { $Matches[1].Trim() } else { "" }
        if (-not (Test-FuzzyNameMatch -A $sw.Name -B $entryName)) { continue }

        $entryDate = Try-ParseDate -DateStr $f06.createdDate
        if (-not $entryDate) { continue }

        $daysDiff = [Math]::Abs(($swDate - $entryDate).TotalDays)
        if ($daysDiff -le 7) {
            # Mark as explained (remove from unexplained persistence list used in Pattern 2)
            $explainedPersistenceKeys[$entryName] = $true
            $explainedFindings += New-Finding -Severity $SEV_INFO `
                -Title "Explained: Run key '$entryName' was created within 7 days of '$($sw.Name)' installation" `
                -Detail "Software installed: $($sw.Date) | Persistence entry: $($f06.createdDate). Sources: Module 05 (software), Module 06 (run key)." `
                -WhyItMatters "Persistence entry creation is temporally consistent with a known software installation — expected install behaviour."
        }
    }
}

# =============================================================================
# PATTERN 5: Orphaned run key with no uninstall record
# =============================================================================
Write-Host "  [5/7] Orphaned run keys vs. software history..."

foreach ($f06 in $mod06findings) {
    if ($f06.title -notmatch 'Run Key Points to Missing File') { continue }

    # Extract executable name from the Value field in the detail string
    $valueStr  = Extract-DetailField -Detail $f06.detail -Field 'Value'
    $exeName   = if ($valueStr) {
        try { [System.IO.Path]::GetFileNameWithoutExtension(($valueStr -split '"' | Where-Object { $_ -match '\.' } | Select-Object -First 1)) } catch { "" }
    } else { "" }
    $entryName = if ($f06.title -match ':\s*(.+)$') { $Matches[1].Trim() } else { "" }

    # Check Module 05 software for a name match (would indicate software was installed and possibly uninstalled)
    $swMatch = $null
    foreach ($sw in $softwareFindings) {
        if ((Test-FuzzyNameMatch -A $entryName -B $sw.Name) -or ($exeName -and (Test-FuzzyNameMatch -A $exeName -B $sw.Name))) {
            $swMatch = $sw
            break
        }
    }

    if ($swMatch) {
        $explainedFindings += New-Finding -Severity $SEV_INFO `
            -Title "Explained: Orphaned run key '$entryName' corresponds to uninstall of '$($swMatch.Name)'" `
            -Detail "A software install record matches this run key. The file may have been removed during uninstall without cleaning the registry. Sources: Module 06 (run key), Module 05 (software)." `
            -WhyItMatters "Orphaned run key is consistent with incomplete uninstallation of a known application."
    } else {
        $correlatedConcerns += New-Finding -Severity $SEV_RED `
            -Title "Correlated Concern: Run key '$entryName' points to missing file with no corresponding uninstall record" `
            -Detail "No installed or recently installed software matches this run key. The referenced file is missing. Sources: Module 06 (run key), Module 05 (software)." `
            -WhyItMatters "An orphaned run key with no known software match may indicate deliberate file deletion after malware execution." `
            -WhyMightBeNormal "Software may have been installed and uninstalled before the 30-day window captured by Module 05."
    }
}

# =============================================================================
# PATTERN 6: Unexpected shutdown correlated with persistence change
# =============================================================================
Write-Host "  [6/7] Unexpected shutdowns vs. persistence creation times..."

foreach ($f09 in $mod09findings) {
    if ($f09.title -notmatch 'Unexpected System Shutdown Recorded') { continue }

    # Extract timestamp from title: "Unexpected System Shutdown Recorded: 2026-03-15 08:30"
    $shutdownDate = $null
    if ($f09.title -match 'Recorded:\s*(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2})') {
        $shutdownDate = Try-ParseDate -DateStr $Matches[1]
    }
    if (-not $shutdownDate) { continue }

    foreach ($f06 in $mod06findings) {
        if (-not $f06.createdDate) { continue }
        $persistDate = Try-ParseDate -DateStr $f06.createdDate
        if (-not $persistDate) { continue }

        $hoursDiff = [Math]::Abs(($shutdownDate - $persistDate).TotalHours)
        if ($hoursDiff -le 24) {
            $persistName = if ($f06.title -match ':\s*(.+)$') { $Matches[1].Trim() } else { $f06.title }
            $correlatedConcerns += New-Finding -Severity $SEV_YELLOW `
                -Title "Correlated Concern: Unexpected shutdown on $($shutdownDate.ToString('yyyy-MM-dd HH:mm')) occurred within 24 hours of persistence change to '$persistName'" `
                -Detail "Shutdown timestamp: $($shutdownDate.ToString('yyyy-MM-dd HH:mm')) | Persistence entry date: $($f06.createdDate). Sources: Module 09 (shutdown), Module 06 (persistence)." `
                -WhyItMatters "An unexpected shutdown occurring close to a persistence change may indicate that a process installing persistence caused an instability, or that a forced shutdown was used to cover tracks." `
                -WhyMightBeNormal "Coincidental timing. Power outage or user-initiated shutdown may overlap with legitimate software installation."
        }
    }
}

# =============================================================================
# PATTERN 7: Strong security posture confirmation
# =============================================================================
Write-Host "  [7/7] Security posture confirmation..."

$defenderActive  = $false
$noDetections    = $false
$lsassPPL        = $false
$wdigestDisabled = $false
$uacEnabled      = $false

foreach ($f03 in $mod03findings) {
    if ($f03.severity -eq "GREEN") {
        if ($f03.title -match 'Defender Antivirus Is Active')           { $defenderActive  = $true }
        if ($f03.title -match 'No Historical Malware Detections')        { $noDetections    = $true }
        if ($f03.title -match 'LSASS Protected Process Light Is Active') { $lsassPPL        = $true }
        if ($f03.title -match 'WDigest.*Disabled')                       { $wdigestDisabled = $true }
        if ($f03.title -match 'UAC Is Enabled')                          { $uacEnabled      = $true }
    }
}

if ($defenderActive -and $noDetections -and $lsassPPL -and $wdigestDisabled -and $uacEnabled) {
    $cleanCorrelations += New-Finding -Severity $SEV_GREEN `
        -Title "Clean Correlation: Strong security posture confirmed across all key controls" `
        -Detail "Defender active with no detections, LSASS protected, WDigest disabled — credential theft risk is low. Source: Module 03 (security config)." `
        -WhyItMatters "All five critical security controls are confirmed active. This significantly reduces the risk of credential theft, undetected malware, and privilege escalation."
} else {
    $missing = @()
    if (-not $defenderActive)  { $missing += "Defender" }
    if (-not $noDetections)    { $missing += "No detections" }
    if (-not $lsassPPL)        { $missing += "LSASS PPL" }
    if (-not $wdigestDisabled) { $missing += "WDigest disabled" }
    if (-not $uacEnabled)      { $missing += "UAC" }
    $cleanCorrelations += New-Finding -Severity $SEV_INFO `
        -Title "Partial Security Posture: $($missing.Count) of 5 key controls not confirmed" `
        -Detail "Controls not confirmed GREEN: $($missing -join ', '). Source: Module 03 (security config)." `
        -WhyItMatters "One or more critical security controls are not confirmed active. Review Module 03 for details."
}

Write-Host ""
Write-Host "[*] Computing noise-adjusted score..."

# =============================================================================
# NOISE-ADJUSTED SCORE
# =============================================================================
# Collect raw totals across all 9 modules
$rawRed    = 0
$rawYellow = 0
$rawGreen  = 0
$rawInfo   = 0

foreach ($key in $moduleData.Keys) {
    $summary = $moduleData[$key].summary
    if ($summary) {
        $rawRed    += if ($summary.red)    { [int]$summary.red }    else { 0 }
        $rawYellow += if ($summary.yellow) { [int]$summary.yellow } else { 0 }
        $rawGreen  += if ($summary.green)  { [int]$summary.green }  else { 0 }
        $rawInfo   += if ($summary.info)   { [int]$summary.info }   else { 0 }
    }
}

# Count explained-away findings by their source severity
$explainedRed    = ($explainedFindings | Where-Object { $_.Severity -eq "RED"    }).Count
$explainedYellow = ($explainedFindings | Where-Object { $_.Severity -eq "YELLOW" }).Count

$adjRed    = [Math]::Max(0, $rawRed    - $explainedRed)
$adjYellow = [Math]::Max(0, $rawYellow - $explainedYellow)
$adjGreen  = $rawGreen
$adjInfo   = $rawInfo

$scoreTableHtml = @"
<div style="background:#1a1d27;border:1px solid #2a2d3a;border-radius:8px;padding:1.2rem;font-family:'Courier New',monospace;font-size:0.85rem;color:#e2e8f0;margin-bottom:1.5rem">
  <div style="color:#64748b;font-size:0.75rem;font-weight:600;letter-spacing:0.08em;text-transform:uppercase;margin-bottom:0.8rem">Noise-Adjusted Score</div>
  <div style="display:grid;grid-template-columns:160px 1fr;gap:0.3rem">
    <span style="color:#64748b">Raw findings:</span>
    <span><span style="color:#ef4444">RED: $rawRed</span>&nbsp;&nbsp;&nbsp;<span style="color:#eab308">YELLOW: $rawYellow</span>&nbsp;&nbsp;&nbsp;<span style="color:#22c55e">GREEN: $rawGreen</span>&nbsp;&nbsp;&nbsp;<span style="color:#3b82f6">INFO: $rawInfo</span></span>
    <span style="color:#64748b">Explained away:</span>
    <span><span style="color:#ef4444">RED: $explainedRed</span>&nbsp;&nbsp;&nbsp;<span style="color:#eab308">YELLOW: $explainedYellow</span></span>
    <span style="color:#64748b;font-weight:700">Adjusted score:</span>
    <span style="font-weight:700"><span style="color:#ef4444">RED: $adjRed</span>&nbsp;&nbsp;&nbsp;<span style="color:#eab308">YELLOW: $adjYellow</span>&nbsp;&nbsp;&nbsp;<span style="color:#22c55e">GREEN: $adjGreen</span>&nbsp;&nbsp;&nbsp;<span style="color:#3b82f6">INFO: $adjInfo</span></span>
  </div>
</div>
"@

# =============================================================================
# ASSEMBLE: Combine into allFindings for JSON output
# =============================================================================
$allFindings += $correlatedConcerns
$allFindings += $explainedFindings
$allFindings += $cleanCorrelations

# =============================================================================
# ASSEMBLE: HTML Report
# =============================================================================
Write-Host "[*] Writing correlation report..."

$concernsHtml = if ($correlatedConcerns.Count -gt 0) {
    ConvertTo-HtmlFindings -Findings $correlatedConcerns
} else {
    "<p class='no-findings'>[OK] No correlated concerns identified.</p>"
}

$explainedHtml = if ($explainedFindings.Count -gt 0) {
    ConvertTo-HtmlFindings -Findings $explainedFindings
} else {
    "<p class='no-findings'>No findings were explained away by correlation.</p>"
}

$cleanHtml = if ($cleanCorrelations.Count -gt 0) {
    ConvertTo-HtmlFindings -Findings $cleanCorrelations
} else {
    "<p class='no-findings'>No clean correlations identified.</p>"
}

$bodyHtml  = $scoreTableHtml
$bodyHtml += ConvertTo-HtmlSection -Title "Correlated Concerns ($($correlatedConcerns.Count))" -Content $concernsHtml
$bodyHtml += ConvertTo-HtmlSection -Title "Explained Findings ($($explainedFindings.Count))" -Content $explainedHtml -StartCollapsed $true
$bodyHtml += ConvertTo-HtmlSection -Title "Clean Correlations ($($cleanCorrelations.Count))" -Content $cleanHtml -StartCollapsed $true

$summaryHtml  = Get-SummaryBar -AllFindings $allFindings
$findingsHtml = ConvertTo-HtmlFindings -Findings $allFindings
$findingsSection = ConvertTo-HtmlSection -Title "All Correlation Findings" -Content $findingsHtml -StartCollapsed $true

$fullHtml  = (Get-HtmlHeader -ModuleTitle $MODULE_TITLE -ModuleNumber $MODULE_NUM -Hostname $HOSTNAME -ScanTime $SCAN_TIME)
$fullHtml += $summaryHtml
$fullHtml += $findingsSection
$fullHtml += $bodyHtml
$fullHtml += Get-HtmlFooter

$fullHtml | Out-File -FilePath $reportFile -Encoding UTF8 -Force

Write-Host ""
Write-Host "[+] Module 10 complete."
Write-Host "    Correlated Concerns:  $($correlatedConcerns.Count)"
Write-Host "    Explained Findings:   $($explainedFindings.Count)"
Write-Host "    Clean Correlations:   $($cleanCorrelations.Count)"
Write-Host "    Report saved to: $reportFile"
Write-Host ""

Write-ModuleJson -ReportDir $reportDir -ModuleNumber $MODULE_NUM -ModuleTitle $MODULE_TITLE `
    -Findings $allFindings -Hostname $HOSTNAME -ScanTime $SCAN_TIME

# =============================================================================
# AI-READY EXPORT: 10_Correlation_Export.txt
# =============================================================================
Write-Host "[*] Writing AI-ready export..."

$exportFile  = Join-Path $reportDir "10_Correlation_Export.txt"
$exportLines = [System.Collections.Generic.List[string]]::new()

$exportLines.Add("WINDOWS FORENSIC TRIAGE TOOLKIT - AI ANALYSIS EXPORT")
$exportLines.Add("Hostname    : $HOSTNAME")
$exportLines.Add("Scan Time   : $SCAN_TIME")
$exportLines.Add("Toolkit Ver : 1.5")
$exportLines.Add("Export Time : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
$exportLines.Add("=" * 70)
$exportLines.Add("")

# --- Section 1: Noise-adjusted score ---
$exportLines.Add("SECTION 1: NOISE-ADJUSTED SCORE SUMMARY")
$exportLines.Add("-" * 40)
$exportLines.Add("Raw findings:   RED: $rawRed  YELLOW: $rawYellow  GREEN: $rawGreen  INFO: $rawInfo")
$exportLines.Add("Explained away: RED: $explainedRed  YELLOW: $explainedYellow")
$exportLines.Add("Adjusted score: RED: $adjRed  YELLOW: $adjYellow  GREEN: $adjGreen  INFO: $adjInfo")
$exportLines.Add("")

# --- Section 2: Correlated concerns ---
$exportLines.Add("SECTION 2: CORRELATED CONCERNS ($($correlatedConcerns.Count))")
$exportLines.Add("-" * 40)
if ($correlatedConcerns.Count -eq 0) {
    $exportLines.Add("No correlated concerns identified.")
    $exportLines.Add("")
} else {
    foreach ($c in $correlatedConcerns) {
        $exportLines.Add("[$($c.Severity)] $($c.Title)")
        $exportLines.Add("  Detail           : $($c.Detail)")
        $exportLines.Add("  Why It Matters   : $($c.WhyItMatters)")
        if (-not [string]::IsNullOrWhiteSpace($c.WhyMightBeNormal)) {
            $exportLines.Add("  May Be Normal If : $($c.WhyMightBeNormal)")
        }
        $exportLines.Add("")
    }
}

# --- Section 3: High-priority findings by module ---
$exportLines.Add("SECTION 3: HIGH-PRIORITY FINDINGS BY MODULE (RED and YELLOW)")
$exportLines.Add("-" * 40)
$exportLines.Add("(Cross-module explanations are listed in Section 4.)")
$exportLines.Add("")

$_modNames = @{
    "01"="System Identity"; "02"="Storage and Files"; "03"="Security Config";
    "04"="Accounts and Auth"; "05"="Processes and Software"; "06"="Persistence";
    "07"="Network Snapshot"; "08"="Network Time Series"; "09"="Forensic Artifacts"
}

$foundAny = $false
foreach ($modNum in @("01","02","03","04","05","06","07","08","09")) {
    $modFindings = Get-ModuleFindings $modNum
    $hiPriority  = @($modFindings | Where-Object { $_.severity -eq "RED" -or $_.severity -eq "YELLOW" })
    if ($hiPriority.Count -eq 0) { continue }
    $foundAny = $true
    $modName = if ($_modNames.ContainsKey($modNum)) { $_modNames[$modNum] } else { "Module $modNum" }
    $exportLines.Add("Module $modNum - $modName ($($hiPriority.Count) findings)")
    foreach ($f in $hiPriority) {
        $exportLines.Add("  [$($f.severity)] $($f.title)")
        if (-not [string]::IsNullOrWhiteSpace($f.detail)) {
            $exportLines.Add("    Detail: $($f.detail)")
        }
    }
    $exportLines.Add("")
}
if (-not $foundAny) {
    $exportLines.Add("No RED or YELLOW findings across modules 01-09.")
    $exportLines.Add("")
}

# --- Section 4: Explained findings summary ---
$exportLines.Add("SECTION 4: EXPLAINED FINDINGS SUMMARY ($($explainedFindings.Count) total)")
$exportLines.Add("-" * 40)
if ($explainedFindings.Count -eq 0) {
    $exportLines.Add("No findings were explained by cross-module correlation.")
} else {
    foreach ($e in $explainedFindings) {
        $exportLines.Add("  $($e.Title)")
    }
}
$exportLines.Add("")

# --- Section 5: Security positives (GREEN) ---
$allGreenFindings = [System.Collections.Generic.List[object]]::new()
foreach ($key in $moduleData.Keys) {
    $mf = $moduleData[$key].findings
    if ($mf) {
        foreach ($f in $mf) {
            if ($f.severity -eq "GREEN") { $allGreenFindings.Add($f) }
        }
    }
}
$exportLines.Add("SECTION 5: SECURITY POSITIVES ($($allGreenFindings.Count) GREEN findings)")
$exportLines.Add("-" * 40)
if ($allGreenFindings.Count -eq 0) {
    $exportLines.Add("No confirmed security positives recorded.")
} else {
    foreach ($g in $allGreenFindings) {
        $exportLines.Add("  [GREEN] $($g.title)")
    }
}
$exportLines.Add("")

# --- Section 6: System context from Module 01 ---
$exportLines.Add("SECTION 6: SYSTEM CONTEXT (from Module 01 - System Identity)")
$exportLines.Add("-" * 40)
$mod01findings = Get-ModuleFindings "01"
if ($mod01findings.Count -eq 0) {
    $exportLines.Add("Module 01 data not available.")
} else {
    foreach ($f in $mod01findings) {
        $exportLines.Add("  [$($f.severity)] $($f.title)")
        if (-not [string]::IsNullOrWhiteSpace($f.detail)) {
            $exportLines.Add("    $($f.detail)")
        }
    }
}
$exportLines.Add("")
$exportLines.Add("=" * 70)
$exportLines.Add("END OF EXPORT")

# Write UTF-8 without BOM (PowerShell 5.1 compatible)
[System.IO.File]::WriteAllLines($exportFile, $exportLines.ToArray(), [System.Text.UTF8Encoding]::new($false))

Write-Host "    AI export saved to: $exportFile"

return @{
    Module = $MODULE_TITLE
    Red    = ($allFindings | Where-Object { $_.Severity -eq "RED"    }).Count
    Yellow = ($allFindings | Where-Object { $_.Severity -eq "YELLOW" }).Count
    Report = $reportFile
}
