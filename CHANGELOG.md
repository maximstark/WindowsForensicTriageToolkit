# Changelog

## 2.0 (2026-10)

**A full desktop app.** The WinForms launcher is replaced by a WPF application.
- **Scan page:** module picker, network-watch length (1, 2, 5 or 10 min), live per-module status, timing and results, running counters, taskbar progress, a collapsible console.
- **Findings page:** verdict banner, severity tiles that filter, search, module filter, master/detail view, **new since last scan** against the previous scan of the same host, and copying a finding.
- **History page:** every scan folder on disk, including folders opened from other machines.
- **Export page:** hand-off summary (copy or save), formula-safe CSV, the HTML report set, and evidence-manifest verification.
- **About page:** live script-integrity status and command-line help.
- Dark native title bar, per-monitor DPI, a modern folder picker, keyboard shortcuts and a new icon.
- `--headless` mode for scripted runs, with the verdict as the exit code. `--open <folder>` opens an existing scan.

**Security**
- Scripts are extracted to an Administrators/SYSTEM-only folder in ProgramData instead of the user's `%TEMP%`, closing a window in which a user-level process could swap a script before the elevated run.
- The SHA-256 of every script is compiled into the exe and verified before each module runs.
- Report HTML now encodes all finding text. Attacker-controlled strings, such as a planted PowerShell history line, could previously inject script into the report.
- The Winlogon safe-list no longer hides `userinit.exe,C:\evil.exe`-style hijacks or masquerading `explorer.exe` copies.
- `powershell.exe` and `taskkill.exe` are run by absolute path. Reports and links open un-elevated.

**Reports**
- New `00_Summary.html` index, `scan.json`, the `scan.log` transcript, and a `manifest.json` with the SHA-256 of every file.
- Fixed: module JSON files were all named `NN_.json`.
- Fixed: the summary bar showed "All Clear" when a module had exactly one finding of a severity (PowerShell 5.1 `.Count`).
- Fixed: PowerShell 5.1 crashed on a three-argument `Join-Path` when the scripts ran from source.
- Fixed: em-dashes in modules 08 and 09 rendered as mojibake.
- Fixed: `00_LAUNCHER.bat` spread modules across separate folders and skipped module 10.
- Fixed: the file walks in modules 02 and 09 followed the legacy `Application Data` junctions, which point back at their own parent. Every file under `%LOCALAPPDATA%` and `ProgramData` was reported over and over (`…\Application Data\Application Data\…`), and the duplicates used up the per-folder cap so real files went unchecked. A new `Get-ChildFilesSafe` never enters reparse points.
- False-positive pass across modules 02, 05, 06, 07, 09 and 10.
- **Noise reduction from a real developer workstation scan.** The same scan went from 124 critical findings to the handful that deserved it:
  - Module 02 reports one finding per executable *family*, so dozens of numbered build-tool copies in Temp are one line, and it no longer scans `%TEMP%` twice when it equals `%LOCALAPPDATA%\Temp`.
  - Module 05 reports one finding per executable with its PIDs, not one per process. Unsigned-with-network is a warning, and the known-unsigned toolchain paths are skipped. Browser → `cmd.exe` (native-messaging hosts) is a warning; Office and PDF readers spawning shells stay critical.
  - Module 06 recognizes Windows' default `SCM Event Log` WMI subscription, but only when its consumer really is the log-only `NTEventLogEventConsumer`.
  - Module 07 rates SSH and RDP listeners as warnings (often deliberate); VNC stays critical.
  - Module 10 rates "run key with no install record" as a warning: per-user, portable and Store apps routinely lack uninstall entries.

**Project**
- `build.ps1` checks that scripts are pure ASCII and that the XAML is well-formed. The version comes from `Common.ps1`.
- A test suite (`tests/Run-Tests.ps1`) runs in CI. The synthetic demo scan lives in `samples/`.

## 1.5 (2026-03)
- Fixed module 02 false positives on web assets in AppData and module 09 Event 4648 SYSTEM false positives.
- Added the `.exe` distribution with GUI progress, and centralized the version constant.

## 1.4
- Encoding fixes for non-UTF-8 systems, plus `$MyInvocation` path resolution.

## 1.0
- First nine-module toolkit with HTML reporting.
