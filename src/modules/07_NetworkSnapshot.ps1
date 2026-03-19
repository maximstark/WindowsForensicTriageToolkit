# =============================================================================
# Module 07 -- Network Snapshot
# Windows Forensic Triage Toolkit
# =============================================================================
# What this module collects:
#   - All listening ports with owning process
#   - All established connections with process names
#   - DNS server configuration (changed DNS = major red flag)
#   - Hosts file contents and integrity check
#   - Proxy settings (unexpected proxy = MITM risk)
#   - ARP cache (recently communicated devices)
#   - DNS resolution cache (what domains has this machine looked up)
#   - NetBIOS name cache
#   - Active SMB connections and open shares
#   - SSH server presence check
#   - VNC server presence check
#   - WinRM status
#   - Network adapter information
#
# Admin required: Partial (most available without admin, shares need elevation)
# Typical runtime: ~60 seconds
# =============================================================================

#Requires -Version 5.1

# Encoding fix - ensures correct display on all Windows code pages
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
. "$ScriptDir\..\lib\Common.ps1"

$MODULE_NUM   = "07"
$MODULE_TITLE = "Network Snapshot"
$SCAN_TIME    = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$HOSTNAME     = $env:COMPUTERNAME

Write-Host ""
Write-Host "============================================"
Write-Host " Module 07 -- Network Snapshot"
Write-Host "============================================"
Write-Host ""

$reportDir  = Initialize-ReportDir -ModuleName $MODULE_TITLE
$reportFile = Join-Path $reportDir "07_NetworkSnapshot.html"

$allFindings = @()
$bodyHtml    = ""

# Known legitimate DNS servers
$KNOWN_DNS_SERVERS = @(
    # ISP/Router (local)
    "192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    # Google
    "8.8.8.8", "8.8.4.4",
    # Cloudflare
    "1.1.1.1", "1.0.0.1",
    # OpenDNS
    "208.67.222.222", "208.67.220.220",
    # Quad9
    "9.9.9.9", "149.112.112.112",
    # Microsoft
    "4.2.2.1", "4.2.2.2",
    # Comcast, AT&T, other major ISPs
    "75.75.75.75", "75.75.76.76",
    # Local loopback
    "127.0.0.1", "::1", "fec0:"
)

# =============================================================================
# COLLECT: Network Adapters
# =============================================================================
Write-Host "[*] Collecting network adapter information..."

$adapters = Invoke-Safe { Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq "Up" } }

$adapterHtml = ""
if ($adapters) {
    $adRows = $adapters | ForEach-Object {
        $ipConfig = Invoke-Safe { Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction Stop | Select-Object -First 1 }
        [PSCustomObject]@{
            "Name"        = $_.Name
            "Description" = $_.InterfaceDescription
            "MAC"         = $_.MacAddress
            "Link Speed"  = $_.LinkSpeed
            "IP Address"  = if ($ipConfig) { $ipConfig.IPAddress } else { "N/A" }
            "Type"        = $_.MediaType
        }
    }
    $adapterHtml = ConvertTo-HtmlTable `
        -Data $adRows `
        -Headers @("Name","Description","MAC","Link Speed","IP Address","Type") `
        -Properties @("Name","Description","MAC","Link Speed","IP Address","Type")
} else {
    $adapterHtml = "<p class='no-findings'>No active network adapters found.</p>"
}

$bodyHtml += ConvertTo-HtmlSection -Title "Active Network Adapters" -Content $adapterHtml

# =============================================================================
# COLLECT: DNS Configuration
# =============================================================================
Write-Host "[*] Checking DNS configuration..."

$dnsHtml     = ""
$dnsServers  = Invoke-Safe { Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop |
               Where-Object { $_.ServerAddresses.Count -gt 0 } }

if ($dnsServers) {
    $dnsRows = $dnsServers | ForEach-Object {
        [PSCustomObject]@{
            "Interface"    = $_.InterfaceAlias
            "DNS Servers"  = $_.ServerAddresses -join ", "
        }
    }
    $dnsHtml = ConvertTo-HtmlTable `
        -Data $dnsRows `
        -Headers @("Interface","DNS Servers") `
        -Properties @("Interface","DNS Servers")

    # Check each DNS server against known good list
    foreach ($dnsEntry in $dnsServers) {
        foreach ($server in $dnsEntry.ServerAddresses) {
            $isKnownDNS = $false
            foreach ($knownPrefix in $KNOWN_DNS_SERVERS) {
                if ($server.StartsWith($knownPrefix) -or $server -eq $knownPrefix) {
                    $isKnownDNS = $true
                    break
                }
            }
            if (-not $isKnownDNS -and $server -ne "" -and $server -ne "0.0.0.0") {
                # v1.5: Downgraded from RED to YELLOW -- unknown DNS deserves review but isn't definitively malicious
                $allFindings += New-Finding -Severity $SEV_YELLOW `
                    -Title "Unrecognized DNS Server: $server" `
                    -Detail "Interface: $($dnsEntry.InterfaceAlias) | DNS: $server" `
                    -WhyItMatters "If your DNS server is controlled by an attacker, every domain you visit can be silently redirected to a malicious IP. Your bank website could point to a phishing page." `
                    -WhyMightBeNormal "Corporate DNS servers, VPN DNS servers, or custom DNS setups. Verify this IP is intentional."
            }
        }
    }

    if (-not $allFindings.Where({$_.Title -match "Unrecognized DNS"})) {
        $allFindings += New-Finding -Severity $SEV_GREEN `
            -Title "DNS Servers Are Recognized" `
            -Detail "All configured DNS servers match known providers (ISP/router, Google, Cloudflare, etc.)" `
            -WhyItMatters "Legitimate DNS servers ensure your domain lookups are not being redirected."
    }
} else {
    $dnsHtml = "<p class='no-findings'>Could not retrieve DNS configuration.</p>"
}

$bodyHtml += ConvertTo-HtmlSection -Title "DNS Server Configuration" -Content $dnsHtml

# =============================================================================
# COLLECT: Hosts File Integrity
# =============================================================================
Write-Host "[*] Checking hosts file..."

$hostsPath = "C:\Windows\System32\drivers\etc\hosts"
$hostsHtml = ""

if (Test-Path $hostsPath -ErrorAction SilentlyContinue) {
    $hostsContent = Get-Content -Path $hostsPath -ErrorAction SilentlyContinue
    $activeEntries = $hostsContent | Where-Object { $_ -notmatch "^\s*#" -and $_.Trim() -ne "" }

    $hostsDisplay = ConvertTo-SafeHtml($hostsContent -join "`n")
    $hostsHtml = "<pre style='font-family:monospace;font-size:0.8rem;color:#94a3b8;white-space:pre-wrap'>$hostsDisplay</pre>"

    if ($activeEntries.Count -gt 2) {
        # More than just localhost entries
        $suspiciousHosts = $activeEntries | Where-Object {
            $_ -notmatch "127\.0\.0\.1\s+localhost" -and
            $_ -notmatch "::1\s+localhost" -and
            $_ -notmatch "127\.0\.0\.1\s+ip6-localhost"
        }
        if ($suspiciousHosts) {
            $allFindings += New-Finding -Severity $SEV_RED `
                -Title "$($suspiciousHosts.Count) Non-Standard Hosts File Entries Found" `
                -Detail "Entries: $($suspiciousHosts -join ' | ')" `
                -WhyItMatters "The hosts file overrides DNS for specific domains. An attacker can redirect your bank's website to a phishing page by adding an entry here. This is completely silent and bypasses all DNS security." `
                -WhyMightBeNormal "Ad-blockers and parental control software sometimes add many entries. Security researchers add known malware domains. Verify each entry."
        }
    } else {
        $allFindings += New-Finding -Severity $SEV_GREEN `
            -Title "Hosts File Contains Only Standard Entries" `
            -Detail "Only localhost entries present. No domain redirections." `
            -WhyItMatters "A clean hosts file means your DNS lookups are not being locally redirected."
    }
} else {
    $hostsHtml = "<p class='no-findings'>Hosts file not found at expected location.</p>"
}

$bodyHtml += ConvertTo-HtmlSection -Title "Hosts File" -Content $hostsHtml

# =============================================================================
# COLLECT: Proxy Settings
# =============================================================================
Write-Host "[*] Checking proxy settings..."

$proxySettings = Invoke-Safe {
    Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction Stop
}

$proxyHtml = "<table><tbody>"
if ($proxySettings) {
    $proxyEnabled = $proxySettings.ProxyEnable
    $proxyServer  = $proxySettings.ProxyServer
    $proxyOverride= $proxySettings.ProxyOverride
    $autoConfig   = $proxySettings.AutoConfigURL

    $proxyColor = if ($proxyEnabled -eq 1) { "#eab308" } else { "#22c55e" }
    $proxyHtml += "<tr><td style='width:220px;color:#94a3b8;font-weight:600'>Proxy Enabled</td><td class='mono' style='color:$proxyColor'>$(if($proxyEnabled -eq 1){'YES'}else{'No'})</td></tr>"
    $proxyHtml += "<tr><td style='color:#94a3b8;font-weight:600'>Proxy Server</td><td class='mono'>$(ConvertTo-SafeHtml($proxyServer))</td></tr>"
    $proxyHtml += "<tr><td style='color:#94a3b8;font-weight:600'>Bypass List</td><td class='mono'>$(ConvertTo-SafeHtml($proxyOverride))</td></tr>"
    $proxyHtml += "<tr><td style='color:#94a3b8;font-weight:600'>Auto-Config URL</td><td class='mono'>$(ConvertTo-SafeHtml($autoConfig))</td></tr>"

    if ($proxyEnabled -eq 1 -and $proxyServer) {
        $allFindings += New-Finding -Severity $SEV_RED `
            -Title "HTTP Proxy Is ENABLED: $proxyServer" `
            -Detail "All web traffic is being routed through: $proxyServer" `
            -WhyItMatters "An unexpected proxy means all your browser traffic passes through a third party who can read, modify, and log everything you send and receive -- including passwords on non-HTTPS sites." `
            -WhyMightBeNormal "Corporate networks, VPNs, and privacy tools like Charles Proxy or Fiddler use proxy settings. Verify this is intentional."
    } elseif ($autoConfig) {
        $allFindings += New-Finding -Severity $SEV_YELLOW `
            -Title "Proxy Auto-Config URL Set: $autoConfig" `
            -Detail "Browser will use PAC file to determine proxy settings." `
            -WhyItMatters "A malicious PAC file can selectively route specific domains through an attacker's proxy." `
            -WhyMightBeNormal "Enterprise environments commonly use PAC files for proxy configuration."
    } else {
        $allFindings += New-Finding -Severity $SEV_GREEN `
            -Title "No Proxy Configured" `
            -Detail "Direct internet connection -- no proxy interception." `
            -WhyItMatters "Traffic is not being routed through a third-party proxy."
    }
}
$proxyHtml += "</tbody></table>"

$bodyHtml += ConvertTo-HtmlSection -Title "Proxy Settings" -Content $proxyHtml

# =============================================================================
# COLLECT: Listening Ports
# =============================================================================
Write-Host "[*] Enumerating listening ports..."

$listeningHtml = ""
try {
    $listening = Get-NetTCPConnection -State Listen -ErrorAction Stop
    $listenRows = $listening | ForEach-Object {
        $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            "Local Address" = $_.LocalAddress
            "Port"          = $_.LocalPort
            "Process"       = if ($proc) { $proc.Name } else { "PID $($_.OwningProcess)" }
            "PID"           = $_.OwningProcess
        }
    } | Sort-Object Port

    $listeningHtml = ConvertTo-HtmlTable `
        -Data $listenRows `
        -Headers @("Local Address","Port","Process","PID") `
        -Properties @("Local Address","Port","Process","PID")

    # Flag SSH (22), VNC (5900), RDP (3389) listening
    $sshListen = $listening | Where-Object { $_.LocalPort -eq 22 }
    $rdpListen = $listening | Where-Object { $_.LocalPort -eq 3389 }
    $vncListen = $listening | Where-Object { $_.LocalPort -in @(5900, 5901, 5902) }

    if ($sshListen) {
        $allFindings += New-Finding -Severity $SEV_RED `
            -Title "SSH Server Is LISTENING on Port 22" `
            -Detail "Process: $(($sshListen | ForEach-Object { (Get-Process -Id $_.OwningProcess -EA SilentlyContinue).Name }) -join ', ')" `
            -WhyItMatters "An SSH server provides remote shell access to this machine. On a home machine this should not be running unless deliberately configured." `
            -WhyMightBeNormal "Windows now includes OpenSSH server as an optional feature. Developers and IT professionals sometimes enable it."
    }
    if ($rdpListen) {
        $allFindings += New-Finding -Severity $SEV_RED `
            -Title "RDP Server Is LISTENING on Port 3389" `
            -Detail "Remote Desktop is accepting inbound connections." `
            -WhyItMatters "An active RDP server allows anyone who can reach this port to attempt to connect remotely. Home edition should not have this active by default." `
            -WhyMightBeNormal "User may have enabled Remote Desktop for legitimate remote work or support."
    }
    if ($vncListen) {
        $allFindings += New-Finding -Severity $SEV_RED `
            -Title "VNC Server Is LISTENING on Port $((($vncListen | Select-Object -First 1).LocalPort))" `
            -Detail "A VNC screen-sharing server is accepting connections." `
            -WhyItMatters "VNC provides full graphical remote access to the desktop. This should not be running unless deliberately installed and configured." `
            -WhyMightBeNormal "User may have installed VNC for legitimate remote support."
    }

    if (-not $sshListen -and -not $rdpListen -and -not $vncListen) {
        $allFindings += New-Finding -Severity $SEV_GREEN `
            -Title "No Remote Access Servers Listening (SSH/RDP/VNC)" `
            -Detail "Ports 22, 3389, 5900-5902 are not in listening state." `
            -WhyItMatters "No standard remote access service is accepting inbound connections."
    }

} catch {
    $listeningHtml = "<p class='no-findings'>Could not retrieve listening ports: $($_.Exception.Message)</p>"
}

$bodyHtml += ConvertTo-HtmlSection -Title "Listening Ports" -Content $listeningHtml

# =============================================================================
# COLLECT: ARP Cache
# =============================================================================
Write-Host "[*] Reading ARP cache..."

$arpOutput = Invoke-Safe { (& arp -a 2>&1) -join "`n" }
$arpHtml   = if ($arpOutput) {
    "<pre style='font-family:monospace;font-size:0.78rem;color:#94a3b8;white-space:pre-wrap'>$(ConvertTo-SafeHtml($arpOutput))</pre>"
    "<p style='color:#64748b;font-size:0.8rem;margin-top:0.5rem'>ARP cache shows devices this machine has recently communicated with on the local network.</p>"
} else {
    "<p class='no-findings'>Could not retrieve ARP cache.</p>"
}

$bodyHtml += ConvertTo-HtmlSection -Title "ARP Cache (Recent Local Network Devices)" -Content $arpHtml -StartCollapsed $true

# =============================================================================
# COLLECT: DNS Cache (Domains Recently Resolved)
# =============================================================================
Write-Host "[*] Reading DNS cache..."

$dnsCache = Invoke-Safe { Get-DnsClientCache -ErrorAction Stop | Sort-Object Entry }

$dnsCacheHtml = ""
if ($dnsCache -and $dnsCache.Count -gt 0) {
    # Look for DGA-like domains (random-looking, high entropy)
    $suspiciousDomains = $dnsCache | Where-Object {
        $entry = $_.Entry
        # Long random-looking subdomains (DGA indicator)
        ($entry -match "^[a-z0-9]{12,}\." -and $entry -notmatch "microsoft|windows|apple|google|amazon|cdn|akamai|cloudfront") -or
        # Direct IP connections (no domain -- suspicious for outbound)
        ($entry -match "^\d+\.\d+\.\d+\.\d+$")
    }

    if ($suspiciousDomains) {
        foreach ($sd in $suspiciousDomains) {
            $allFindings += New-Finding -Severity $SEV_YELLOW `
                -Title "Potentially Suspicious DNS Entry: $($sd.Entry)" `
                -Detail "Type: $($sd.Type) | Data: $($sd.Data)" `
                -WhyItMatters "Randomly-generated looking domain names are associated with Domain Generation Algorithm (DGA) malware that contacts different C2 servers daily." `
                -WhyMightBeNormal "Some CDN providers and advertising networks use long randomized subdomains legitimately."
        }
    }

    $cacheRows = $dnsCache | Select-Object -First 150 | ForEach-Object {
        [PSCustomObject]@{
            "Domain"  = $_.Entry
            "Type"    = $_.Type
            "Data"    = $_.Data
            "TTL"     = $_.TimeToLive
        }
    }
    $dnsCacheHtml = "<p style='color:#64748b;font-size:0.82rem;margin-bottom:0.8rem'>Showing up to 150 cached DNS entries (domains recently resolved by this machine).</p>"
    $dnsCacheHtml += ConvertTo-HtmlTable `
        -Data $cacheRows `
        -Headers @("Domain","Type","Data","TTL") `
        -Properties @("Domain","Type","Data","TTL")
} else {
    $dnsCacheHtml = "<p class='no-findings'>DNS cache is empty or could not be retrieved.</p>"
}

$bodyHtml += ConvertTo-HtmlSection -Title "DNS Cache (Recently Resolved Domains)" -Content $dnsCacheHtml -StartCollapsed $true

# =============================================================================
# COLLECT: Open Shares
# =============================================================================
Write-Host "[*] Checking network shares..."

$sharesHtml = ""
try {
    $shares = Get-SmbShare -ErrorAction Stop |
              Where-Object { $_.Name -notmatch "^(ADMIN|IPC|[A-Z])\$$" }

    if ($shares -and $shares.Count -gt 0) {
        $shareRows = $shares | ForEach-Object {
            [PSCustomObject]@{
                "Share Name" = $_.Name
                "Path"       = $_.Path
                "Description"= $_.Description
                "Access"     = $_.ShareState
            }
        }
        $sharesHtml = ConvertTo-HtmlTable `
            -Data $shareRows `
            -Headers @("Share Name","Path","Description","Access") `
            -Properties @("Share Name","Path","Description","Access")

        $allFindings += New-Finding -Severity $SEV_YELLOW `
            -Title "$($shares.Count) Non-Default Network Share(s) Found" `
            -Detail "Shares: $(($shares | Select-Object -ExpandProperty Name) -join ', ')" `
            -WhyItMatters "Open network shares allow other computers to access files on this machine. Unexpected shares may indicate attacker-created access points." `
            -WhyMightBeNormal "Home media sharing, printer sharing, or intentional file sharing between home devices."
    } else {
        $sharesHtml = "<p class='no-findings'>? No non-default network shares found.</p>"
        $allFindings += New-Finding -Severity $SEV_GREEN `
            -Title "No Unexpected Network Shares" `
            -Detail "Only default administrative shares (ADMIN$, IPC$, C$) are present." `
            -WhyItMatters "Open shares can provide unauthorized file access to other network devices."
    }
} catch {
    $sharesHtml = "<p class='no-findings'>Could not enumerate shares: $($_.Exception.Message). Run as Administrator.</p>"
}

$bodyHtml += ConvertTo-HtmlSection -Title "Network Shares" -Content $sharesHtml

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
Write-Host "[+] Module 07 complete."
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
