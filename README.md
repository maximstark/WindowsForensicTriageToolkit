# Windows Forensic Triage Toolkit

**A portable, read-only Windows forensic triage tool that produces styled HTML reports with a traffic-light severity system.**

Download the latest `.exe` from [Releases](../../releases), run it on any Windows 10/11 machine, and get a comprehensive security assessment in under 15 minutes — no installation, no PowerShell knowledge, no configuration required.

---

## What It Does

The toolkit runs 9 forensic assessment modules in sequence and produces individual HTML reports for each:

| # | Module | What It Checks |
|---|--------|---------------|
| 01 | System Identity | Hardware model, serial, BIOS, OS version, install date, timezone |
| 02 | Storage & Files | Partitions, BitLocker, executables in suspicious locations, Prefetch, PS history |
| 03 | Security Config | Defender status, Secure Boot, TPM, UAC, LSASS protection, firewall, VBS |
| 04 | Accounts & Auth | Local accounts, admin group, RDP history, failed logons, password policy |
| 05 | Processes & Software | Running processes, RAT detection, unsigned binaries, installed programs |
| 06 | Persistence | Registry run keys, scheduled tasks, services, WMI subscriptions, IFEO |
| 07 | Network Snapshot | DNS config, hosts file, listening ports, shares, proxy settings |
| 08 | Network Time Series | 5-minute live connection monitoring with reverse DNS identification |
| 09 | Forensic Artifacts | USB history, Security event log analysis, crash dumps, browser profiles |

### Report Features
- Dark terminal aesthetic with collapsible sections
- Traffic light severity system: RED (critical) → YELLOW (warning) → GREEN (clean) → INFO
- Every finding includes "Why It Matters" and "May Be Normal" context
- Machine-readable metadata for automated processing

---

## Quick Start

### Option A: Download the compiled .exe (recommended for end users)

1. Download `TriageToolkit.exe` from the [latest release](../../releases)
2. Copy it to the target machine (USB drive, network share, etc.)
3. Double-click to run — the UAC prompt will appear automatically
4. Wait for the scan to complete (~10-15 minutes)
5. Reports open automatically in your default browser and are saved to your Desktop

### Option B: Run from PowerShell source (for transparency or contribution)

1. Clone this repository
2. Open PowerShell as Administrator
3. Navigate to the `src/modules/` directory
4. Run individual modules:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\01_SystemIdentity.ps1
   ```
   Or use the batch launcher:
   ```cmd
   .\00_LAUNCHER.bat
   ```

### Option C: Build from source

1. Clone this repository
2. Open PowerShell (no admin needed for the build itself)
3. Run the build script:
   ```powershell
   .\build.ps1
   ```
4. The compiled .exe appears in `build\TriageToolkit.exe`
5. The build uses only `csc.exe` from the .NET Framework — no additional tools required

---

## What This Tool Does NOT Do

**This is a strictly read-only forensic tool.** It is important to state clearly what it does not do:

- **No registry writes** — does not modify any registry keys
- **No file modifications** — does not create, modify, or delete any files on the target system (reports are written to a new directory only)
- **No software installation** — nothing is installed, no services created, no scheduled tasks
- **No network calls** — makes no outbound network connections, except Module 08 which performs reverse DNS lookups (`Resolve-DnsName`) on observed connection IPs for identification purposes only
- **No persistence** — leaves no trace on the system after the report directory is created
- **No remediation** — identifies issues but does not attempt to fix them

The tool operates in the same way as opening Task Manager, Event Viewer, or Device Manager — it reads existing system state and presents it in a structured format.

---

## System Requirements

- Windows 10 or Windows 11
- PowerShell 5.1 or later (built into all modern Windows)
- Administrator privileges recommended (some checks work without, but results will be incomplete)
- .NET Framework 4.x (pre-installed on all Windows 10/11)

---

## Repository Structure

```
├── src/
│   ├── lib/
│   │   └── Common.ps1          # Shared library (HTML generation, utilities, constants)
│   ├── modules/
│   │   ├── 01_SystemIdentity.ps1
│   │   ├── 02_StorageAndFiles.ps1
│   │   ├── 03_SecurityConfig.ps1
│   │   ├── 04_AccountsAndAuth.ps1
│   │   ├── 05_ProcessesAndSoftware.ps1
│   │   ├── 06_Persistence.ps1
│   │   ├── 07_NetworkSnapshot.ps1
│   │   ├── 08_NetworkTimeSeries.ps1
│   │   └── 09_ForensicArtifacts.ps1
│   ├── TriageLauncher.cs       # .NET wrapper source (GUI, elevation, packaging)
│   └── TriageLauncher.manifest # UAC application manifest
├── build.ps1                   # Build script — compiles .exe from source
├── 00_LAUNCHER.bat             # Batch launcher for direct PowerShell execution
├── docs/
│   └── ARCHITECTURE.md         # Technical architecture documentation
├── .github/
│   └── workflows/
│       └── build.yml           # GitHub Actions CI pipeline
├── CONTRIBUTING.md
├── SECURITY.md
├── LICENSE
└── README.md
```

---

## Building from Source

The build process is designed to be fully reproducible with zero additional tooling:

```powershell
# Clone the repo
git clone https://github.com/YOUR_USERNAME/windows-forensic-triage.git
cd windows-forensic-triage

# Build (uses csc.exe from .NET Framework — already on your machine)
.\build.ps1

# Output: build\TriageToolkit.exe
```

The build script:
1. Locates `csc.exe` from the .NET Framework installation
2. Embeds all `.ps1` files as compiled resources inside the .exe
3. Embeds the UAC manifest for automatic elevation
4. Computes SHA256 hashes of all embedded scripts
5. Outputs `build\TriageToolkit.exe` plus `build\checksums.json`

### Verifying a Release

Every release includes `checksums.json` containing SHA256 hashes of all embedded PowerShell scripts. You can verify a release binary by:

1. Building from the same tagged source commit
2. Comparing `checksums.json` between your local build and the release

---

## Version History

| Version | Changes |
|---------|---------|
| 1.5 | Fixed Module 02 false positives on web assets in AppData. Fixed Module 09 Event 4648 SYSTEM false positives. Added .exe distribution with GUI progress. Version constant centralized. |
| 1.4 | Encoding fixes for non-UTF-8 systems. `$MyInvocation` path resolution. |
| 1.0 | Initial 9-module toolkit with HTML reporting. |

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Disclaimer

This tool is provided for legitimate security assessment, incident response, and forensic triage purposes only. It is a read-only tool that makes no modifications to the system under examination. The authors assume no liability for misuse. Always obtain proper authorization before running security assessment tools on systems you do not own.
