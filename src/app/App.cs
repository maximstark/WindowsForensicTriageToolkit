// =============================================================================
// App.cs -- entry point: desktop app, --headless runner, --render-docs
// =============================================================================
// Windows Forensic Triage Toolkit v2
// WPF on .NET Framework 4.8 (in-box on Windows 10/11). Built by build.ps1 with
// the csc.exe that ships with Windows -- no SDK, no NuGet, no XAML compiler:
// the XAML is embedded and parsed at runtime.
// =============================================================================

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Windows;
using System.Windows.Markup;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;

// Opt in to .NET 4.8 runtime behaviour (per-monitor DPI, modern WPF quirks).
// Without it, an exe compiled by the in-box csc runs in 4.0 compatibility mode.
[assembly: TargetFramework(".NETFramework,Version=v4.8", FrameworkDisplayName = ".NET Framework 4.8")]
[assembly: AssemblyTitle("Windows Forensic Triage Toolkit")]
[assembly: AssemblyProduct("Windows Forensic Triage Toolkit")]
[assembly: AssemblyDescription("Portable, read-only Windows forensic triage")]
[assembly: AssemblyCompany("Maxim Stark")]
[assembly: AssemblyCopyright("MIT License")]
[assembly: AssemblyVersion(TriageToolkit.BuildInfo.AssemblyVersion)]
[assembly: AssemblyFileVersion(TriageToolkit.BuildInfo.AssemblyVersion)]
[assembly: AssemblyInformationalVersion(TriageToolkit.BuildInfo.Version)]

namespace TriageToolkit
{
    public static class App
    {
        [STAThread]
        static int Main(string[] args)
        {
            var a = new Args(args);
            if (a.Has("--headless") || a.Has("--help") || a.Has("-h") || a.Has("/?") || a.Has("--version"))
                return Headless.Run(a);

            var app = new Application { ShutdownMode = ShutdownMode.OnMainWindowClose };
            app.Resources = (ResourceDictionary)XamlReader.Parse(ReadResource("ui.Theme.xaml"));
            app.DispatcherUnhandledException += (s, e) =>
            {
                MessageBox.Show("Something went wrong:\n\n" + e.Exception.Message +
                                "\n\nThe current scan's reports on disk are unaffected.", "Triage Toolkit",
                                MessageBoxButton.OK, MessageBoxImage.Error);
                e.Handled = true;
            };

            var win = new MainWindow();
            if (a.Has("--render-docs"))
            {
                DocsRenderer.Attach(win, a.Value("--render-docs"), a.Value("--scan"), a.Value("--baseline"));
                win.WindowStartupLocation = WindowStartupLocation.Manual;
                win.Left = -20000;
                win.ShowActivated = false;
            }
            else if (!string.IsNullOrEmpty(a.Value("--open")))
            {
                string dir = a.Value("--open");
                win.Loaded += (s, e) => { win.LoadScan(dir); win.Nav("Findings"); };
            }
            return app.Run(win);
        }

        public static bool IsAdministrator()
        {
            using (var id = WindowsIdentity.GetCurrent())
                return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
        }

        public static string ReadResource(string name)
        {
            using (var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("TriageToolkit." + name))
            {
                if (s == null) throw new FileNotFoundException("Missing embedded resource " + name);
                using (var r = new StreamReader(s, Encoding.UTF8))
                    return r.ReadToEnd();
            }
        }

        public static ImageSource LoadIcon()
        {
            try
            {
                var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("TriageToolkit.ui.app.ico");
                return s == null ? null : BitmapFrame.Create(s, BitmapCreateOptions.None, BitmapCacheOption.OnLoad);
            }
            catch { return null; }
        }
    }

    public sealed class Args
    {
        readonly List<string> list;
        public Args(string[] args) { list = args.ToList(); }
        public bool Has(string flag) { return list.Any(x => string.Equals(x, flag, StringComparison.OrdinalIgnoreCase)); }
        public string Value(string flag)
        {
            int i = list.FindIndex(x => string.Equals(x, flag, StringComparison.OrdinalIgnoreCase));
            return i >= 0 && i + 1 < list.Count && !list[i + 1].StartsWith("--") ? list[i + 1] : null;
        }
    }

    // -------------------------------------------------------------------------
    // --headless: scripted runs for incident response. Exit code is the verdict.
    // -------------------------------------------------------------------------
    static class Headless
    {
        const int Clean = 0, Warnings = 1, Critical = 2, Error = 3;

        public static int Run(Args a)
        {
            if (!Native.AttachConsole(-1)) { /* no parent console: run silently, scan.log has everything */ }
            try
            {
                var stdout = new StreamWriter(Console.OpenStandardOutput(), new UTF8Encoding(false)) { AutoFlush = true };
                Console.SetOut(stdout);
            }
            catch { }
            Console.WriteLine();

            if (a.Has("--version")) { Console.WriteLine("Windows Forensic Triage Toolkit " + BuildInfo.Version); return Clean; }
            if (!a.Has("--headless")) { PrintHelp(); return Clean; }

            if (!App.IsAdministrator())
                Console.WriteLine("[WARN] Not running as administrator -- several checks will be incomplete.");

            var opts = new ScanOptions { OutputRoot = a.Value("--out") ?? ScanEngine.DefaultOutputRoot() };
            string mods = a.Value("--modules");
            if (!string.IsNullOrEmpty(mods))
                opts.Modules = mods.Split(new[] { ',', ' ' }, StringSplitOptions.RemoveEmptyEntries).Select(Pad).ToList();
            string skip = a.Value("--skip");
            if (!string.IsNullOrEmpty(skip))
            {
                var s = skip.Split(new[] { ',', ' ' }, StringSplitOptions.RemoveEmptyEntries).Select(Pad).ToList();
                opts.Modules = opts.Modules.Where(m => !s.Contains(m)).ToList();
            }
            int nm;
            if (int.TryParse(a.Value("--net-minutes"), NumberStyles.Integer, CultureInfo.InvariantCulture, out nm))
                opts.NetMinutes = Math.Max(1, Math.Min(30, nm));

            var unknown = opts.Modules.Where(m => ModuleCatalog.ByNumber(m) == null).ToList();
            if (unknown.Count > 0) { Console.WriteLine("Unknown module(s): " + string.Join(", ", unknown)); return Error; }
            if (opts.Modules.Count == 0) { Console.WriteLine("No modules selected."); return Error; }

            Console.WriteLine("Windows Forensic Triage Toolkit " + BuildInfo.Version + " -- headless scan of " + Environment.MachineName);
            var engine = new ScanEngine();
            bool quiet = a.Has("--quiet");
            engine.Log += (text, kind) =>
            {
                if (!quiet || kind == LogKind.Heading || kind == LogKind.Good || kind == LogKind.Error)
                    Console.WriteLine(text);
            };
            Console.CancelKeyPress += (s, e) => { e.Cancel = true; engine.Cancel(); };

            var result = engine.Run(opts);
            Console.WriteLine();
            if (result.Error != null) { Console.WriteLine("Scan stopped: " + result.Error); return Error; }

            var scan = ScanLoader.LooksLikeScanFolder(result.ReportDir) ? ScanLoader.Load(result.ReportDir) : null;
            if (scan == null) { Console.WriteLine("No results were produced."); return Error; }
            var v = Verdict.For(scan.Red, scan.Yellow);
            Console.WriteLine(v.Title.ToUpperInvariant());
            Console.WriteLine(string.Format(CultureInfo.InvariantCulture, "  critical {0}   warning {1}   clean {2}   info {3}", scan.Red, scan.Yellow, scan.Green, scan.Info));
            foreach (var f in scan.AllFindings.Where(x => x.Severity == Severity.Red).Take(15))
                Console.WriteLine("  [RED] " + f.ModuleNumber + " " + f.Title);
            Console.WriteLine();
            Console.WriteLine("Reports: " + result.ReportDir);
            if (result.Cancelled) return Error;
            return scan.Red > 0 ? Critical : scan.Yellow > 0 ? Warnings : Clean;
        }

        static string Pad(string m)
        {
            int n;
            return int.TryParse(m.Trim(), out n) ? n.ToString("00", CultureInfo.InvariantCulture) : m.Trim();
        }

        static void PrintHelp()
        {
            Console.WriteLine("Windows Forensic Triage Toolkit " + BuildInfo.Version);
            Console.WriteLine();
            Console.WriteLine("  TriageToolkit.exe                     open the desktop app");
            Console.WriteLine("  TriageToolkit.exe --open <scan dir>   open the app on an existing scan folder");
            Console.WriteLine("  TriageToolkit.exe --headless [options]  scan without a window");
            Console.WriteLine();
            Console.WriteLine("  --out <dir>          report root (default: Logs next to the exe)");
            Console.WriteLine("  --modules 01,03,06   run only these modules");
            Console.WriteLine("  --skip 08            leave these modules out");
            Console.WriteLine("  --net-minutes <n>    module 08 watch length, 1-30 (default 5)");
            Console.WriteLine("  --quiet              print module headings and results only");
            Console.WriteLine();
            Console.WriteLine("  Exit code: 0 clean, 1 warnings, 2 critical, 3 error/cancelled.");
            Console.WriteLine("  From cmd use: start /wait TriageToolkit.exe --headless");
            Console.WriteLine();
            Console.WriteLine("  Modules:");
            foreach (var m in ModuleCatalog.All)
                Console.WriteLine("    " + m.Number + "  " + m.Name);
        }
    }

    // -------------------------------------------------------------------------
    // --render-docs <out> --scan <dir> [--baseline <dir>]
    // Renders each page to PNG from a scan folder; used to make the README
    // screenshots from the synthetic demo scan in samples/.
    // -------------------------------------------------------------------------
    static class DocsRenderer
    {
        public static void Attach(MainWindow win, string outDir, string scanDir, string baselineDir)
        {
            Directory.CreateDirectory(outDir);
            // demo folders come from tools\New-DemoScan.ps1, which can't write the C#-generated files
            foreach (var d in new[] { scanDir, baselineDir })
            {
                if (string.IsNullOrEmpty(d) || !ScanLoader.LooksLikeScanFolder(d)) continue;
                var s = ScanLoader.Load(d);
                ReportWriter.WriteSummaryHtml(s);
                ReportWriter.WriteManifest(d, s.Hostname);
            }
            win.Vm.OutputRoot = Path.GetDirectoryName(Path.GetDirectoryName(Path.GetFullPath(scanDir)));

            var steps = new Queue<Action>();
            string realRoot = win.Vm.OutputRoot;
            steps.Enqueue(() =>
            {
                win.LoadScan(scanDir);
                win.MaskForDocs("DEMO-WS01", realRoot, @"E:\Triage\Logs");
                win.Nav("Findings");
            });
            steps.Enqueue(() => Snap(win, outDir, "findings.png"));
            steps.Enqueue(() =>
            {
                var red = win.Vm.FindingsView.Cast<FindingVM>().FirstOrDefault(f => f.IsNew) ?? win.Vm.FindingsView.Cast<FindingVM>().FirstOrDefault();
                if (red != null) win.Vm.Selected = red;
            });
            steps.Enqueue(() => Snap(win, outDir, "findings-new.png"));
            steps.Enqueue(() => win.Nav("History"));
            steps.Enqueue(() => Snap(win, outDir, "history.png"));
            steps.Enqueue(() => win.Nav("Export"));
            steps.Enqueue(() => Snap(win, outDir, "export.png"));
            steps.Enqueue(() => win.Nav("About"));
            steps.Enqueue(() => Snap(win, outDir, "about.png"));
            steps.Enqueue(() => win.Nav("Scan"));
            steps.Enqueue(() => Snap(win, outDir, "scan-setup.png"));
            steps.Enqueue(() => FakeRunning(win));
            steps.Enqueue(() => Snap(win, outDir, "scan-running.png"));
            steps.Enqueue(() => { win.Vm.IsRunning = false; win.Close(); });

            var timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(700) };
            timer.Tick += (s, e) =>
            {
                if (steps.Count == 0) { timer.Stop(); return; }
                steps.Dequeue()();
            };
            // give the async history scan time to land before the first step
            win.Loaded += (s, e) => { timer.Interval = TimeSpan.FromMilliseconds(700); timer.Start(); };
        }

        static void Snap(MainWindow win, string outDir, string name)
        {
            var el = (FrameworkElement)win.Content;
            el.UpdateLayout();
            const double dpi = 144;
            int w = (int)Math.Round(el.ActualWidth * dpi / 96), h = (int)Math.Round(el.ActualHeight * dpi / 96);
            var bmp = new RenderTargetBitmap(w, h, dpi, dpi, PixelFormats.Pbgra32);
            bmp.Render(el);
            var enc = new PngBitmapEncoder();
            enc.Frames.Add(BitmapFrame.Create(bmp));
            using (var fs = File.Create(Path.Combine(outDir, name))) enc.Save(fs);
        }

        // A plausible mid-scan state built from the loaded demo results.
        static void FakeRunning(MainWindow win)
        {
            var vm = win.Vm;
            win.FreezeForDocs();
            var scan = vm.Scan;
            int red = 0, yellow = 0, green = 0, info = 0;
            string[] times = { "14s", "1m 21s", "27s", "38s" };
            for (int i = 0; i < vm.Modules.Count; i++)
            {
                var m = vm.Modules[i];
                m.IsSelected = true;
                m.CanToggle = false;
                if (i < 4)
                {
                    var r = scan.Modules.FirstOrDefault(x => x.Module == m.Number);
                    m.State = ModuleOutcome.Completed;
                    m.ElapsedText = times[i];
                    m.ShowResult(r);
                    if (r != null) { red += r.Red; yellow += r.Yellow; green += r.Green; info += r.Info; }
                }
                else if (i == 4) { m.State = ModuleOutcome.Running; m.ElapsedText = "52s"; }
            }
            vm.LiveRed = red; vm.LiveYellow = yellow; vm.LiveGreen = green; vm.LiveInfo = info;
            vm.IsRunning = true;
            vm.Progress = 34;
            vm.TimeText = "3m 32s";
            vm.StageText = "Module 5 of 10  ·  Processes & Software";
            win.AppendLogForDocs("[05] Processes & Software", LogKind.Heading);
            win.AppendLogForDocs("[*] Enumerating running processes and verifying signatures...", LogKind.Plain);
            win.AppendLogForDocs("[*] Checking 212 processes against known remote-access tools", LogKind.Plain);
        }
    }
}
