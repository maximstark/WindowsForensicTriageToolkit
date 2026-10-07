// =============================================================================
// ScanEngine.cs -- extracts the embedded modules and runs them
// =============================================================================
// Security model for the elevated run:
//   * Scripts are extracted to a freshly created, randomly named directory
//     directly under %ProgramData% whose ACL is set at creation time to
//     Administrators + SYSTEM only (no inheritance). A standard user can't
//     write into it, and can't rename it either, because ProgramData doesn't
//     grant them delete-child. v1.5 extracted into the user's %TEMP%, where
//     any process running as that user could swap a script between
//     extraction and the elevated PowerShell reading it.
//   * Every script's SHA-256 is checked against the hash compiled into the
//     exe by build.ps1 (BuildInfo.ScriptHashes) at extraction and again
//     immediately before each module starts.
//   * powershell.exe is launched by absolute System32 path, never via PATH.
// =============================================================================

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace TriageToolkit
{
    public enum LogKind { Plain, Heading, Good, Warn, Error }

    public enum ModuleOutcome { Pending, Running, Completed, Failed, TimedOut, Cancelled, Skipped }

    public sealed class ScanOptions
    {
        public List<string> Modules = ModuleCatalog.All.Select(m => m.Number).ToList();
        public int NetMinutes = 5;
        public string OutputRoot = "";
    }

    public sealed class ModuleRun
    {
        public ModuleDef Def;
        public ModuleOutcome Outcome = ModuleOutcome.Pending;
        public TimeSpan Elapsed;
        public ModuleResult Result;
        public int ExitCode;
    }

    public sealed class ScanResult
    {
        public string ReportDir = "";
        public DateTime Started, Finished;
        public bool Cancelled;
        public string Error;
        public List<ModuleRun> Runs = new List<ModuleRun>();

        public int Completed { get { return Runs.Count(r => r.Outcome == ModuleOutcome.Completed); } }
    }

    public sealed class ScanEngine
    {
        public event Action<string, LogKind> Log;
        public event Action<ModuleRun> ModuleStarted;
        public event Action<ModuleRun> ModuleFinished;
        public event Action<ModuleRun, double> ModuleProgress;   // 0..1 within the module, when known

        volatile bool cancelRequested;
        Process current;
        readonly object procLock = new object();
        StreamWriter logFile;                      // <report dir>\scan.log, the full console transcript
        readonly object logLock = new object();

        static readonly Regex PollLine = new Regex(@"\[Poll (\d+)/(\d+)\]");

        public void Cancel()
        {
            cancelRequested = true;
            lock (procLock)
            {
                if (current != null) KillTree(current);
            }
        }

        public static string DefaultOutputRoot()
        {
            string exeDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            string preferred = Path.Combine(exeDir, "Logs");
            if (IsWritable(exeDir)) return preferred;
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "TriageToolkit", "Logs");
        }

        public static string PowerShellPath()
        {
            string sys = Environment.Is64BitOperatingSystem && !Environment.Is64BitProcess
                ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Sysnative")
                : Environment.SystemDirectory;
            return Path.Combine(sys, @"WindowsPowerShell\v1.0\powershell.exe");
        }

        // Blocking. Run on a worker thread.
        public ScanResult Run(ScanOptions opts)
        {
            var result = new ScanResult { Started = DateTime.Now };
            string host = Environment.MachineName;
            string root = string.IsNullOrWhiteSpace(opts.OutputRoot) ? DefaultOutputRoot() : opts.OutputRoot;
            result.ReportDir = Path.Combine(root, host, result.Started.ToString("yyyy-MM-dd_HH-mm-ss", CultureInfo.InvariantCulture));

            // Correlation always runs last and only makes sense with something to correlate.
            var selected = ModuleCatalog.All.Where(m => opts.Modules.Contains(m.Number)).ToList();
            foreach (var def in ModuleCatalog.All)
            {
                var run = new ModuleRun { Def = def };
                if (!selected.Contains(def)) run.Outcome = ModuleOutcome.Skipped;
                result.Runs.Add(run);
            }

            string workspace = null;
            try
            {
                Directory.CreateDirectory(result.ReportDir);
                try { logFile = new StreamWriter(Path.Combine(result.ReportDir, "scan.log"), false, new UTF8Encoding(false)) { AutoFlush = true }; }
                catch { logFile = null; }
                Emit("Windows Forensic Triage Toolkit " + BuildInfo.Version + " on " + host + " as " + Environment.UserDomainName + "\\" + Environment.UserName +
                     " (" + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture) + ")", LogKind.Plain);
                Emit("Report folder: " + result.ReportDir, LogKind.Plain);

                workspace = CreateLockedWorkspace();
                ExtractScripts(workspace);
                Emit("Extracted " + ModuleCatalog.ScriptResources.Length + " scripts to a locked workspace; all SHA-256 hashes match the build.", LogKind.Good);

                foreach (var run in result.Runs)
                {
                    if (run.Outcome == ModuleOutcome.Skipped) continue;
                    if (cancelRequested) { run.Outcome = ModuleOutcome.Cancelled; continue; }
                    RunModule(run, workspace, result.ReportDir, opts);
                }
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
                Emit("[FAIL] " + ex.Message, LogKind.Error);
            }
            finally
            {
                if (workspace != null) DeleteWorkspace(workspace);
            }

            result.Cancelled = cancelRequested;
            result.Finished = DateTime.Now;
            Emit(result.Cancelled ? "Scan cancelled." : "Scan finished in " + Format.Duration(result.Finished - result.Started) + ".", LogKind.Plain);

            if (Directory.Exists(result.ReportDir))
            {
                try
                {
                    var scan = ScanLoader.Load(result.ReportDir);
                    ReportWriter.WriteScanMeta(result, opts);
                    if (scan.Modules.Count > 0) ReportWriter.WriteSummaryHtml(scan);
                    Emit("Wrote 00_Summary.html; manifest.json (SHA-256 of every report file) is written last.", LogKind.Good);
                    CloseLog();
                    ReportWriter.WriteManifest(result.ReportDir, host);
                }
                catch (Exception ex)
                {
                    Emit("[WARN] Could not write summary files: " + ex.Message, LogKind.Warn);
                }
            }
            CloseLog();
            return result;
        }

        void CloseLog()
        {
            lock (logLock)
            {
                if (logFile != null) { logFile.Dispose(); logFile = null; }
            }
        }

        void RunModule(ModuleRun run, string workspace, string reportDir, ScanOptions opts)
        {
            var def = run.Def;
            string script = Path.Combine(workspace, "modules", def.File);
            run.Outcome = ModuleOutcome.Running;
            Emit("", LogKind.Plain);
            Emit("[" + def.Number + "] " + def.Name, LogKind.Heading);
            Raise(ModuleStarted, run);

            var sw = Stopwatch.StartNew();
            try
            {
                VerifyScript(script, def.File);
                VerifyScript(Path.Combine(workspace, "lib", "Common.ps1"), "Common.ps1");

                var psi = new ProcessStartInfo
                {
                    FileName = PowerShellPath(),
                    Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"" + script + "\"",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                    WorkingDirectory = Path.GetDirectoryName(script),
                    StandardOutputEncoding = Encoding.UTF8,
                    StandardErrorEncoding = Encoding.UTF8,
                };
                psi.EnvironmentVariables["TRIAGE_REPORT_DIR"] = reportDir;
                psi.EnvironmentVariables["TRIAGE_NET_MINUTES"] = opts.NetMinutes.ToString(CultureInfo.InvariantCulture);

                // Generous ceiling so a wedged WMI/event-log query can't stall the scan forever.
                int limitSeconds = def.IsNetworkWatch ? opts.NetMinutes * 60 + 600 : 900;

                using (var proc = new Process { StartInfo = psi })
                {
                    proc.OutputDataReceived += (s, e) =>
                    {
                        if (e.Data == null) return;
                        Emit(e.Data, Classify(e.Data));
                        var m = PollLine.Match(e.Data);
                        if (m.Success)
                        {
                            double a = double.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture);
                            double b = double.Parse(m.Groups[2].Value, CultureInfo.InvariantCulture);
                            if (b > 0) RaiseProgress(run, Math.Min(1.0, a / b) * 0.9);
                        }
                    };
                    proc.ErrorDataReceived += (s, e) =>
                    {
                        if (!string.IsNullOrEmpty(e.Data)) Emit(e.Data, LogKind.Warn);
                    };

                    lock (procLock) { current = proc; }
                    proc.Start();
                    proc.BeginOutputReadLine();
                    proc.BeginErrorReadLine();

                    bool timedOut = false;
                    while (!proc.WaitForExit(250))
                    {
                        if (cancelRequested) break;
                        if (sw.Elapsed.TotalSeconds > limitSeconds) { timedOut = true; break; }
                    }
                    if (!proc.HasExited)
                    {
                        KillTree(proc);
                        proc.WaitForExit(5000);
                    }
                    else
                    {
                        proc.WaitForExit(); // flush async readers
                    }
                    lock (procLock) { current = null; }

                    run.ExitCode = proc.HasExited ? proc.ExitCode : -1;
                    if (cancelRequested) run.Outcome = ModuleOutcome.Cancelled;
                    else if (timedOut) run.Outcome = ModuleOutcome.TimedOut;
                    else run.Outcome = ModuleOutcome.Completed;
                }
            }
            catch (Exception ex)
            {
                run.Outcome = ModuleOutcome.Failed;
                Emit("[FAIL] " + ex.Message, LogKind.Error);
            }
            sw.Stop();
            run.Elapsed = sw.Elapsed;

            if (run.Outcome == ModuleOutcome.Completed)
            {
                run.Result = LoadModuleResult(reportDir, def.Number);
                if (run.Result == null)
                {
                    // The script ran but produced no JSON -- treat as a failure so it's visible.
                    run.Outcome = ModuleOutcome.Failed;
                    Emit("[FAIL] " + def.Name + " exited (code " + run.ExitCode + ") without writing its results.", LogKind.Error);
                }
                else
                {
                    Emit(string.Format(CultureInfo.InvariantCulture, "[OK] {0} finished in {1}", def.Name, Format.Duration(run.Elapsed)), LogKind.Good);
                }
            }
            else if (run.Outcome == ModuleOutcome.TimedOut)
            {
                Emit("[FAIL] " + def.Name + " exceeded its time limit and was stopped.", LogKind.Error);
            }
            Raise(ModuleFinished, run);
        }

        static ModuleResult LoadModuleResult(string reportDir, string number)
        {
            try
            {
                var scan = ScanLoader.Load(reportDir);
                return scan.Modules.FirstOrDefault(m => m.Module == number);
            }
            catch { return null; }
        }

        static LogKind Classify(string line)
        {
            string t = line.TrimStart();
            if (t.StartsWith("[!]") || t.StartsWith("[WARN]") || t.StartsWith("[RED]")) return LogKind.Warn;
            if (t.StartsWith("[FAIL]") || t.StartsWith("[ERR")) return LogKind.Error;
            if (t.StartsWith("[OK]") || t.StartsWith("[+]")) return LogKind.Good;
            return LogKind.Plain;
        }

        // ---------------------------------------------------------------------
        // Workspace
        // ---------------------------------------------------------------------
        static string CreateLockedWorkspace()
        {
            string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            var sec = new DirectorySecurity();
            sec.SetAccessRuleProtection(true, false);
            var inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
            sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
            sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));

            for (int attempt = 0; attempt < 5; attempt++)
            {
                string dir = Path.Combine(programData, "TriageToolkit-run-" + Guid.NewGuid().ToString("N"));
                // Directory.CreateDirectory silently reuses an existing folder (and its ACL),
                // so only ever create a name nobody else could have pre-created.
                if (Directory.Exists(dir) || File.Exists(dir)) continue;
                Directory.CreateDirectory(dir, sec);
                Directory.CreateDirectory(Path.Combine(dir, "lib"));
                Directory.CreateDirectory(Path.Combine(dir, "modules"));
                return dir;
            }
            throw new IOException("Could not create a private script workspace under " + programData);
        }

        static void ExtractScripts(string workspace)
        {
            foreach (string name in ModuleCatalog.ScriptResources)
            {
                string target = name == "Common.ps1"
                    ? Path.Combine(workspace, "lib", name)
                    : Path.Combine(workspace, "modules", name);
                using (Stream s = Assembly.GetExecutingAssembly().GetManifestResourceStream("TriageToolkit.scripts." + name))
                {
                    if (s == null) throw new FileNotFoundException("Embedded script missing: " + name);
                    using (var fs = new FileStream(target, FileMode.CreateNew, FileAccess.Write))
                        s.CopyTo(fs);
                }
                VerifyScript(target, name);
            }
        }

        static void VerifyScript(string path, string name)
        {
            string expected;
            if (!BuildInfo.ScriptHashes.TryGetValue(name, out expected))
                throw new InvalidOperationException("No build-time hash recorded for " + name);
            string actual = Sha256File(path);
            if (!string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Integrity check failed for " + name + " -- the script on disk does not match the build. Scan stopped.");
        }

        static void DeleteWorkspace(string dir)
        {
            for (int i = 0; i < 6; i++)
            {
                try
                {
                    if (Directory.Exists(dir)) Directory.Delete(dir, true);
                    return;
                }
                catch { Thread.Sleep(500); }
            }
        }

        // ---------------------------------------------------------------------
        // Embedded-script verification for the About page
        // ---------------------------------------------------------------------
        public static List<KeyValuePair<string, bool>> VerifyEmbeddedScripts()
        {
            var list = new List<KeyValuePair<string, bool>>();
            foreach (string name in ModuleCatalog.ScriptResources)
            {
                bool ok = false;
                try
                {
                    using (Stream s = Assembly.GetExecutingAssembly().GetManifestResourceStream("TriageToolkit.scripts." + name))
                    {
                        string expected;
                        ok = s != null && BuildInfo.ScriptHashes.TryGetValue(name, out expected) &&
                             string.Equals(Sha256Stream(s), expected, StringComparison.OrdinalIgnoreCase);
                    }
                }
                catch { }
                list.Add(new KeyValuePair<string, bool>(name, ok));
            }
            return list;
        }

        public static string Sha256File(string path)
        {
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
                return Sha256Stream(fs);
        }

        public static string Sha256Stream(Stream s)
        {
            using (var sha = SHA256.Create())
                return BitConverter.ToString(sha.ComputeHash(s)).Replace("-", "");
        }

        // ---------------------------------------------------------------------
        // Helpers
        // ---------------------------------------------------------------------
        static void KillTree(Process p)
        {
            try
            {
                var tk = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "taskkill.exe"),
                    "/T /F /PID " + p.Id.ToString(CultureInfo.InvariantCulture))
                { CreateNoWindow = true, UseShellExecute = false };
                using (var k = Process.Start(tk)) { k.WaitForExit(5000); }
            }
            catch { }
            try { if (!p.HasExited) p.Kill(); } catch { }
        }

        static bool IsWritable(string dir)
        {
            try
            {
                string probe = Path.Combine(dir, ".triage-write-test-" + Guid.NewGuid().ToString("N"));
                File.WriteAllText(probe, "");
                File.Delete(probe);
                return true;
            }
            catch { return false; }
        }

        void Emit(string text, LogKind kind)
        {
            lock (logLock)
            {
                if (logFile != null) { try { logFile.WriteLine(text); } catch { } }
            }
            var h = Log;
            if (h != null) h(text, kind);
        }

        void Raise(Action<ModuleRun> h, ModuleRun run)
        {
            if (h != null) h(run);
        }

        void RaiseProgress(ModuleRun run, double p)
        {
            var h = ModuleProgress;
            if (h != null) h(run, p);
        }
    }

    public static class Format
    {
        public static string Duration(TimeSpan t)
        {
            if (t.TotalSeconds < 1) return "<1s";
            if (t.TotalMinutes < 1) return ((int)t.TotalSeconds).ToString(CultureInfo.InvariantCulture) + "s";
            if (t.TotalHours < 1) return string.Format(CultureInfo.InvariantCulture, "{0}m {1:00}s", (int)t.TotalMinutes, t.Seconds);
            return string.Format(CultureInfo.InvariantCulture, "{0}h {1:00}m", (int)t.TotalHours, t.Minutes);
        }

        public static string Minutes(int seconds)
        {
            if (seconds < 60) return "<1 min";
            return string.Format(CultureInfo.InvariantCulture, "~{0} min", (int)Math.Round(seconds / 60.0));
        }

        public static string Plural(int n, string one, string many)
        {
            return n.ToString(CultureInfo.InvariantCulture) + " " + (n == 1 ? one : many);
        }
    }
}
