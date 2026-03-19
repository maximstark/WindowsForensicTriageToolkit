# =============================================================================
# Module 08 -- Network Time Series
# Windows Forensic Triage Toolkit
# =============================================================================
# What this module does:
#   - Polls all established TCP connections every 30 seconds for 5 minutes
#   - Identifies connections that persist across multiple polls (C2 heartbeats)
#   - Performs reverse DNS lookup on all unique remote IPs
#   - Attempts to identify IP ownership (ISP/company)
#   - Flags connections to unusual ports or unknown organizations
#   - Captures network adapter byte counters (sent/received totals)
#   - Produces a time-series table showing connection stability
#
# Admin required: No
# Typical runtime: 5 minutes (polling period) + ~30s for DNS lookups
#
# Note: Run this module AFTER the machine has been connected to the internet
#       for a few minutes so any persistent connections have had time to establish.
# =============================================================================

#Requires -Version 5.1

# Encoding fix - ensures correct display on all Windows code pages
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
. "$ScriptDir\..\lib\Common.ps1"

$MODULE_NUM   = "08"
$MODULE_TITLE = "Network Time Series"
$SCAN_TIME    = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$HOSTNAME     = $env:COMPUTERNAME

$POLL_INTERVAL_SECONDS = 30
$POLL_COUNT            = 10   # 10 polls x 30s = 5 minutes total

Write-Host ""
Write-Host "============================================"
Write-Host " Module 08 -- Network Time Series"
Write-Host "============================================"
Write-Host ""
Write-Host "  Polling connections every $POLL_INTERVAL_SECONDS seconds"
Write-Host "  Total monitoring time: $([math]::Round($POLL_COUNT * $POLL_INTERVAL_SECONDS / 60, 1)) minutes"
Write-Host "  Do not close this window."
Write-Host ""

$reportDir  = Initialize-ReportDir -ModuleName $MODULE_TITLE
$reportFile = Join-Path $reportDir "08_NetworkTimeSeries.html"

$allFindings  = @()
$bodyHtml     = ""

# =============================================================================
# CAPTURE: Network Adapter Baseline
# =============================================================================
Write-Host "[*] Capturing network adapter baseline..."
$adapterBaseline = Invoke-Safe { Get-NetAdapterStatistics -ErrorAction Stop }
$baselineTime    = Get-Date

# =============================================================================
# POLL: Connection Time Series
# =============================================================================

# Track all unique connections seen: key = "IP:Port:ProcessName"
$connectionLog   = [System.Collections.Generic.List[PSObject]]::new()
$uniqueConns     = @{}   # key -> times seen count

for ($poll = 1; $poll -le $POLL_COUNT; $poll++) {
    $pollTime = Get-Date
    Write-Host "  [Poll $poll/$POLL_COUNT] $(Get-Date -Format 'HH:mm:ss') -- sampling connections..."

    try {
        $conns = Get-NetTCPConnection -State Established -ErrorAction Stop

        foreach ($conn in $conns) {
            # Skip loopback
            if ($conn.RemoteAddress -eq "127.0.0.1" -or $conn.RemoteAddress -eq "::1") { continue }

            $proc    = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            $procName= if ($proc) { $proc.Name } else { "PID $($conn.OwningProcess)" }
            $connKey = "$($conn.RemoteAddress):$($conn.RemotePort):$procName"

            if ($uniqueConns.ContainsKey($connKey)) {
                $uniqueConns[$connKey]++
            } else {
                $uniqueConns[$connKey] = 1
            }

            $connectionLog.Add([PSCustomObject]@{
                Poll          = $poll
                Time          = $pollTime.ToString("HH:mm:ss")
                RemoteAddress = $conn.RemoteAddress
                RemotePort    = $conn.RemotePort
                LocalPort     = $conn.LocalPort
                Process       = $procName
                PID           = $conn.OwningProcess
                Key           = $connKey
            })
        }
    } catch {}

    if ($poll -lt $POLL_COUNT) {
        Start-Sleep -Seconds $POLL_INTERVAL_SECONDS
    }
}

Write-Host ""
Write-Host "[*] Polling complete. Analyzing results..."

# =============================================================================
# CAPTURE: Network Adapter Final + Delta
# =============================================================================
$adapterFinal = Invoke-Safe { Get-NetAdapterStatistics -ErrorAction Stop }
$finalTime    = Get-Date
$monitoringSeconds = ($finalTime - $baselineTime).TotalSeconds

$adapterDeltaHtml = ""
if ($adapterBaseline -and $adapterFinal) {
    $deltaRows = @()
    foreach ($final in $adapterFinal) {
        $baseline = $adapterBaseline | Where-Object { $_.Name -eq $final.Name }
        if ($baseline) {
            $sentMB     = [math]::Round(($final.SentBytes - $baseline.SentBytes) / 1MB, 2)
            $receivedMB = [math]::Round(($final.ReceivedBytes - $baseline.ReceivedBytes) / 1MB, 2)
            $deltaRows += [PSCustomObject]@{
                "Adapter"          = $final.Name
                "Sent (MB)"        = $sentMB
                "Received (MB)"    = $receivedMB
                "Monitoring Period"= "$([math]::Round($monitoringSeconds / 60, 1)) min"
            }

            # Flag very high outbound transfer (potential exfiltration)
            if ($sentMB -gt 50) {
                $allFindings += New-Finding -Severity $SEV_YELLOW `
                    -Title "High Outbound Data Transfer: $sentMB MB in $([math]::Round($monitoringSeconds/60,1)) minutes" `
                    -Detail "Adapter: $($final.Name) | Sent: $sentMB MB | Received: $receivedMB MB" `
                    -WhyItMatters "Large outbound transfers could indicate data exfiltration. Expected outbound from Windows Update, OneDrive sync, or backup software is typically much smaller over 5 minutes." `
                    -WhyMightBeNormal "Windows Update downloading patches, OneDrive uploading files, or a video call can produce large transfers."
            }
        }
    }
    $adapterDeltaHtml = ConvertTo-HtmlTable `
        -Data $deltaRows `
        -Headers @("Adapter","Sent (MB)","Received (MB)","Monitoring Period") `
        -Properties @("Adapter","Sent (MB)","Received (MB)","Monitoring Period")
}

$bodyHtml += ConvertTo-HtmlSection -Title "Network Traffic During Monitoring Period" -Content $adapterDeltaHtml

# =============================================================================
# ANALYZE: Persistent Connections
# =============================================================================

# A connection seen in 3+ polls (90+ seconds) is considered persistent
$persistentConns = $uniqueConns.GetEnumerator() |
                   Where-Object { $_.Value -ge 3 } |
                   Sort-Object Value -Descending

$persistentRows = @()
foreach ($pc in $persistentConns) {
    $parts   = $pc.Key -split ":"
    $remoteIP= $parts[0]
    $remotePort = $parts[1]
    $procName= $parts[2]
    $seenCount = $pc.Value
    $seenSeconds = $seenCount * $POLL_INTERVAL_SECONDS

    $persistentRows += [PSCustomObject]@{
        "Remote IP"      = $remoteIP
        "Remote Port"    = $remotePort
        "Process"        = $procName
        "Times Seen"     = "$seenCount/$POLL_COUNT polls"
        "Min Duration"   = "${seenSeconds}s+"
    }
}

$persistHtml = if ($persistentRows.Count -gt 0) {
    "<p style='color:#64748b;font-size:0.82rem;margin-bottom:0.8rem'>Connections seen in 3 or more polls (90+ seconds) -- these are stable, ongoing connections.</p>"
    (ConvertTo-HtmlTable `
        -Data $persistentRows `
        -Headers @("Remote IP","Remote Port","Process","Times Seen","Min Duration") `
        -Properties @("Remote IP","Remote Port","Process","Times Seen","Min Duration"))
} else {
    "<p class='no-findings'>? No persistent long-duration connections detected during monitoring period.</p>"
    $allFindings += New-Finding -Severity $SEV_GREEN `
        -Title "No Persistent Background Connections Detected" `
        -Detail "No connection remained established for 90+ seconds during the monitoring period." `
        -WhyItMatters "C2 (Command and Control) malware typically maintains a persistent heartbeat connection to its server."
}

$bodyHtml += ConvertTo-HtmlSection -Title "Persistent Connections (90+ Seconds)" -Content $persistHtml

# =============================================================================
# ANALYZE: Reverse DNS Lookup on All Unique IPs
# =============================================================================
Write-Host "[*] Performing reverse DNS lookups on unique IPs..."

$uniqueIPs   = $connectionLog | Select-Object -ExpandProperty RemoteAddress -Unique
$dnsResults  = @()

foreach ($ip in $uniqueIPs) {
    if ($ip -eq "127.0.0.1" -or $ip -eq "::1") { continue }

    $reverseDNS  = ""
    $orgInfo     = ""
    $isSuspPort  = $false

    # Reverse DNS
    try {
        $dns        = [System.Net.Dns]::GetHostEntry($ip)
        $reverseDNS = $dns.HostName
    } catch {
        $reverseDNS = "(no reverse DNS)"
    }

    # Check if connected on suspicious port
    $connsForIP     = $connectionLog | Where-Object { $_.RemoteAddress -eq $ip }
    $portsForIP     = $connsForIP | Select-Object -ExpandProperty RemotePort -Unique
    $processesForIP = $connsForIP | Select-Object -ExpandProperty Process -Unique

    foreach ($port in $portsForIP) {
        if ($SUSPICIOUS_PORTS -contains [int]$port) { $isSuspPort = $true }
    }

    # Classify by reverse DNS
    $classification = if ($reverseDNS -match "microsoft|msn|windows|azure|live\.com|outlook") {
        "Microsoft"
    } elseif ($reverseDNS -match "google|googleapis|gstatic|ggpht") {
        "Google"
    } elseif ($reverseDNS -match "akamai|akamaitech|edgekey") {
        "Akamai CDN"
    } elseif ($reverseDNS -match "cloudfront|amazonaws") {
        "Amazon/AWS"
    } elseif ($reverseDNS -match "cloudflare") {
        "Cloudflare"
    } elseif ($reverseDNS -match "hp\.com|hpcloud|hpe\.com") {
        "HP"
    } elseif ($reverseDNS -match "amd\.com") {
        "AMD"
    } elseif ($reverseDNS -match "realtek") {
        "Realtek"
    } elseif ($reverseDNS -eq "(no reverse DNS)") {
        "?? No reverse DNS -- verify manually"
    } else {
        "Unknown -- verify"
    }

    # Task 8: RFC 1918 private address check
    $isPrivateIP = ($ip -match '^10\.') -or
                   ($ip -match '^192\.168\.') -or
                   ($ip -match '^172\.(1[6-9]|2[0-9]|3[01])\.')

    # Task 8: Vendor map lookup -- find first recognized process for this IP
    $vendorName = ""
    foreach ($procName in $processesForIP) {
        if ($ProcessVendorMap.ContainsKey($procName)) {
            $vendorName = $ProcessVendorMap[$procName]
            break
        }
    }

    $dnsResults += [PSCustomObject]@{
        "Remote IP"      = $ip
        "Reverse DNS"    = $reverseDNS
        "Classification" = $classification
        "Processes"      = ($processesForIP -join ", ")
        "Ports"          = ($portsForIP -join ", ")
        "Susp. Port"     = if ($isSuspPort) { "?? YES" } else { "" }
    }

    if ($isSuspPort) {
        # Task 8: RFC 1918 always downgrades to INFO; otherwise stays RED
        if ($isPrivateIP) {
            $allFindings += New-Finding -Severity $SEV_INFO `
                -Title "Connection to Suspicious Port on $ip" `
                -Detail "Ports: $($portsForIP -join ', ') | Processes: $($processesForIP -join ', ') | Reverse DNS: $reverseDNS | Private network address — local network traffic" `
                -WhyItMatters "These ports are commonly associated with reverse shells, C2 frameworks, and remote access tools." `
                -WhyMightBeNormal "Destination is a private/local network address — traffic is confined to the local network."
        } else {
            $allFindings += New-Finding -Severity $SEV_RED `
                -Title "Connection to Suspicious Port on $ip" `
                -Detail "Ports: $($portsForIP -join ', ') | Processes: $($processesForIP -join ', ') | Reverse DNS: $reverseDNS" `
                -WhyItMatters "These ports are commonly associated with reverse shells, C2 frameworks, and remote access tools." `
                -WhyMightBeNormal "Some legitimate software uses non-standard ports. Research the remote IP and owning organization."
        }
    }

    # v1.5: Only flag unknown IPs if they are also on a suspicious port or persisted the full window
    $isPersistentUnknown = ($uniqueConns.GetEnumerator() | Where-Object { $_.Key -like "${ip}:*" -and $_.Value -ge ($POLL_COUNT - 1) }).Count -gt 0
    if (($classification -match "Unknown|No reverse DNS") -and ($isSuspPort -or $isPersistentUnknown)) {
        $detail = "Reverse DNS: $reverseDNS | Ports: $($portsForIP -join ', ') | Process: $($processesForIP -join ', ')"
        # Task 8: Apply RFC 1918 and vendor map downgrade logic
        if ($isPrivateIP) {
            $connSeverity = $SEV_INFO
            $detail += " | Private network address — local network traffic"
        } elseif ($vendorName) {
            $connSeverity = $SEV_INFO
            $detail += " | Process is recognized $vendorName software"
        } else {
            $connSeverity = $SEV_YELLOW
        }
        $allFindings += New-Finding -Severity $connSeverity `
            -Title "Connection to Unidentified IP: $ip" `
            -Detail $detail `
            -WhyItMatters "Cannot identify the owner of this IP address. All legitimate Windows background services connect to identifiable Microsoft/vendor infrastructure." `
            -WhyMightBeNormal "CDNs and cloud services sometimes return unexpected reverse DNS. Research the IP at https://www.whois.com/whois/$ip"
    }
}

$dnsHtml = if ($dnsResults.Count -gt 0) {
    ConvertTo-HtmlTable `
        -Data ($dnsResults | Sort-Object Classification) `
        -Headers @("Remote IP","Reverse DNS","Classification","Processes","Ports","Susp. Port") `
        -Properties @("Remote IP","Reverse DNS","Classification","Processes","Ports","Susp. Port")
} else {
    "<p class='no-findings'>No established connections were observed during the monitoring period.</p>"
}

$bodyHtml += ConvertTo-HtmlSection -Title "Remote IP Identification (Reverse DNS)" -Content $dnsHtml

# =============================================================================
# DISPLAY: Full Connection Log
# =============================================================================

$logRows = $connectionLog | Select-Object Poll, Time, RemoteAddress, RemotePort, LocalPort, Process

$logHtml = if ($logRows.Count -gt 0) {
    "<p style='color:#64748b;font-size:0.82rem;margin-bottom:0.8rem'>Complete connection log across all $POLL_COUNT polls. Each row is one connection observed at that poll time.</p>"
    (ConvertTo-HtmlTable `
        -Data $logRows `
        -Headers @("Poll","Time","Remote IP","Remote Port","Local Port","Process") `
        -Properties @("Poll","Time","RemoteAddress","RemotePort","LocalPort","Process"))
} else {
    "<p class='no-findings'>No established connections observed during monitoring period.</p>"
}

$bodyHtml += ConvertTo-HtmlSection -Title "Full Connection Log" -Content $logHtml -StartCollapsed $true

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
Write-Host "[+] Module 08 complete."
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
