# Architecture

The toolkit is two layers that meet at a folder of JSON files.

```
TriageToolkit.exe (WPF, .NET Framework 4.8)
 ├─ ScanEngine      extracts + verifies scripts, runs modules one at a time
 │    └─ powershell.exe -File NN_Module.ps1   (env: TRIAGE_REPORT_DIR, TRIAGE_NET_MINUTES)
 │          └─ writes NN_Module.html + NN_Title.json into the report folder
 ├─ ScanLoader      reads NN_*.json back (from this run, or any copied folder)
 ├─ ReportWriter    adds scan.json, 00_Summary.html, manifest.json; CSV export
 ├─ HistoryStore    history = scan folders on disk (+ the v1.5 history file, read-only)
 └─ MainWindow      XAML views + view-models
```

## PowerShell layer (`src/lib`, `src/modules`)

Each module is a standalone script. It dot-sources `lib/Common.ps1` for constants, safe collection wrappers (`Invoke-Safe`, `Get-RegValue`, `Get-SafeEventLog`), publisher checks, `New-Finding`, and the HTML and JSON writers. A module collects data, emits findings, and writes two files:

- `NN_ModuleName.html`: the human report (dark theme, collapsible sections).
- `NN_Module_Title.json`: `{ module, title, hostname, scanTime, version, admin, findings[], summary{} }`.

Module 10 reads every other module's JSON from the same folder and applies correlation patterns (dormant-account tasks, run keys versus install dates, connections versus installed vendors, posture checks). It also writes `10_Correlation_Export.txt`.

Rules for scripts:
- **ASCII only.** PowerShell 5.1 reads UTF-8 files without a BOM as ANSI. `build.ps1` and the tests enforce this.
- **Every finding explains itself.** It needs `WhyItMatters`, and `WhyMightBeNormal` for anything that isn't GREEN.
- **Strictly read-only.** See the "What it changes" section of the README.

The scripts also run without the exe: `src/00_LAUNCHER.bat`, or any single module on its own. Without `TRIAGE_REPORT_DIR` they write to `src/Logs/<HOST>/<timestamp>/`.

## App layer (`src/app`, `src/ui`)

The build uses only the in-box `csc.exe` (C# 5), which drives a few choices:

- **XAML is embedded and parsed at runtime** (`XamlReader.Parse`) instead of compiled. `Theme.xaml` becomes `Application.Resources` before `MainWindow.xaml` is parsed, so `StaticResource` lookups resolve. Named elements are wired in `MainWindow.cs`, and everything else is data binding to `MainViewModel`.
- **`[assembly: TargetFramework(".NETFramework,Version=v4.8")]`** opts the exe into 4.8 runtime behavior, including per-monitor DPI. Without it, a raw csc build runs in 4.0 compatibility mode.
- **JSON** goes through `System.Web.Extensions`' `JavaScriptSerializer`, which is in-box. A small indenting writer in `ReportWriter` makes the files the app writes readable.

`build.ps1` hashes each script and generates `BuildInfo.g.cs`, which holds the version and a `ScriptHashes` table. `ScanEngine` refuses to run a script whose hash differs. The rest of the security model is in the README.

### Scan flow

1. Create `<root>\<HOST>\<yyyy-MM-dd_HH-mm-ss>\` and open `scan.log`.
2. Create `%ProgramData%\TriageToolkit-run-<guid>` with an Administrators+SYSTEM-only ACL, extract the scripts, and verify the hashes.
3. For each selected module in order: verify the hash again, start PowerShell, stream stdout into the UI and `scan.log`, and parse `[Poll n/m]` lines from module 08 for progress. Enforce a time limit. Read the module's JSON back to show its counts.
4. Write `scan.json` and `00_Summary.html`, close `scan.log`, then write `manifest.json` last so it covers everything else.
5. Delete the workspace.

### Docs mode

`--render-docs <out> --scan <dir> [--baseline <dir>]` opens the real window off-screen on a scan folder and renders every page with `RenderTargetBitmap`. The README screenshots come from the synthetic scan made by `tools/New-DemoScan.ps1`, which uses the real `Common.ps1` writers. The test suite uses the same path as a smoke test of the UI.
