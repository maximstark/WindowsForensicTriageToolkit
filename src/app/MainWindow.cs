// =============================================================================
// MainWindow.cs -- loads MainWindow.xaml and drives it
// =============================================================================

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Markup;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Imaging;
using System.Windows.Shell;
using System.Windows.Threading;

namespace TriageToolkit
{
    public sealed class MainWindow : Window
    {
        public readonly MainViewModel Vm = new MainViewModel();
        readonly FrameworkElement root;
        readonly Dictionary<string, FrameworkElement> pages = new Dictionary<string, FrameworkElement>();

        ScanEngine engine;
        DateTime scanStarted;
        ModuleRun currentRun;
        DateTime currentStarted;
        double currentFraction = -1;
        readonly HashSet<string> extraFolders = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        readonly ConcurrentQueue<KeyValuePair<string, LogKind>> logQueue = new ConcurrentQueue<KeyValuePair<string, LogKind>>();
        readonly DispatcherTimer tick;
        RichTextBox console;
        int consoleLines;

        public MainWindow()
        {
            Title = "Windows Forensic Triage Toolkit";
            Width = 1320; Height = 860;
            MinWidth = 1080; MinHeight = 680;
            WindowStartupLocation = WindowStartupLocation.CenterScreen;
            Background = (Brush)Application.Current.Resources["Bg"];
            Icon = App.LoadIcon();
            TaskbarItemInfo = new TaskbarItemInfo();

            root = (FrameworkElement)XamlReader.Parse(App.ReadResource("ui.MainWindow.xaml"));
            Content = root;
            DataContext = Vm;

            foreach (var n in new[] { "Scan", "Findings", "History", "Export", "About" })
                pages[n] = E<FrameworkElement>("Page" + n);
            console = E<RichTextBox>("Console");

            Vm.IsAdmin = App.IsAdministrator();
            Vm.OutputRoot = ScanEngine.DefaultOutputRoot();
            VerifyIntegrity();
            Wire();

            tick = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromMilliseconds(120) };
            tick.Tick += (s, e) => OnTick();
            tick.Start();

            SourceInitialized += (s, e) => Native.UseDarkTitleBar(new WindowInteropHelper(this).Handle, 0x0B, 0x0D, 0x12);
            Loaded += (s, e) => RefreshHistory(openNewest: true);
        }

        T E<T>(string name) where T : class
        {
            var o = root.FindName(name) as T;
            if (o == null) throw new InvalidOperationException("MainWindow.xaml is missing element " + name);
            return o;
        }

        void Click(string name, Action a)
        {
            E<ButtonBase>(name).Click += (s, e) => a();
        }

        // =====================================================================
        // Wiring
        // =====================================================================
        void Wire()
        {
            foreach (var n in pages.Keys.ToList())
            {
                string page = n;
                E<RadioButton>("Nav" + page).Checked += (s, e) => ShowPage(page);
            }

            // network watch segments
            var nets = new Dictionary<string, int> { { "Net1", 1 }, { "Net2", 2 }, { "Net5", 5 }, { "Net10", 10 } };
            foreach (var kv in nets)
            {
                int minutes = kv.Value;
                var rb = E<RadioButton>(kv.Key);
                rb.IsChecked = Vm.NetMinutes == minutes;
                rb.Checked += (s, e) => Vm.NetMinutes = minutes;
            }

            Click("BtnQuick", () => { foreach (var m in Vm.Modules) m.IsSelected = !m.Def.IsNetworkWatch; });
            Click("BtnAll", () => { foreach (var m in Vm.Modules) m.IsSelected = true; });
            Click("BtnChangeOut", ChangeOutputRoot);
            Click("BtnOpenOut", () => { Directory.CreateDirectory(Vm.OutputRoot); ShellOpen(Vm.OutputRoot); });
            Click("BtnStart", StartScan);
            Click("BtnCancel", CancelScan);
            Click("BtnViewFindings", () => Nav("Findings"));
            Click("BtnDoneHtml", OpenSummaryHtml);
            Click("BtnNewScan", () => { Vm.ScanFinished = false; foreach (var m in Vm.Modules) { m.Reset(); m.CanToggle = true; } });

            var consoleToggle = E<ToggleButton>("BtnConsole");
            consoleToggle.Checked += (s, e) => { E<Border>("ConsoleHost").Visibility = Visibility.Visible; consoleToggle.Content = "Hide"; console.ScrollToEnd(); };
            consoleToggle.Unchecked += (s, e) => { E<Border>("ConsoleHost").Visibility = Visibility.Collapsed; consoleToggle.Content = "Show"; };
            Click("BtnCopyLog", () => CopyText(new TextRange(console.Document.ContentStart, console.Document.ContentEnd).Text, "Output copied"));

            Click("BtnFindHtml", OpenSummaryHtml);
            Click("BtnFindFolder", () => { if (Vm.Scan != null) ShellOpen(Vm.Scan.Folder); });
            Click("BtnCopyFinding", () => { if (Vm.Selected != null) CopyText(Vm.Selected.AsText(), "Finding copied"); });
            Click("BtnModuleReport", () => { if (Vm.Selected != null && Vm.Selected.HasReport) ShellOpen(Vm.Selected.HtmlPath); });
            Click("BtnEmptyScan", () => Nav("Scan"));
            Click("BtnEmptyOpen", OpenScanFolder);

            Click("BtnHistOpen", OpenScanFolder);
            Click("BtnHistRefresh", () => RefreshHistory(false));

            Click("BtnCopyExport", () => { if (Vm.HasExport) CopyText(Vm.ExportPreview, "Summary copied"); else Toast("This scan has no hand-off summary"); });
            Click("BtnSaveExport", SaveExport);
            Click("BtnCsv", SaveCsv);
            Click("BtnExpHtml", OpenSummaryHtml);
            Click("BtnExpFolder", () => { if (Vm.Scan != null) ShellOpen(Vm.Scan.Folder); });
            Click("BtnVerify", VerifyManifest);
            Click("BtnGitHub", () => ShellOpen("https://github.com/maximstark/WindowsForensicTriageToolkit"));

            var list = E<ListBox>("FindingsList");
            list.KeyDown += (s, e) =>
            {
                if (e.Key == Key.C && Keyboard.Modifiers == ModifierKeys.Control && Vm.Selected != null)
                {
                    CopyText(Vm.Selected.AsText(), "Finding copied");
                    e.Handled = true;
                }
            };
            list.MouseDoubleClick += (s, e) => { if (Vm.Selected != null && Vm.Selected.HasReport) ShellOpen(Vm.Selected.HtmlPath); };

            PreviewKeyDown += OnKey;
        }

        void OnKey(object sender, KeyEventArgs e)
        {
            var mods = Keyboard.Modifiers;
            if (mods == ModifierKeys.Control)
            {
                string[] order = { "Scan", "Findings", "History", "Export", "About" };
                int idx = e.Key - Key.D1;
                if (idx >= 0 && idx < order.Length) { Nav(order[idx]); e.Handled = true; return; }
                if (e.Key == Key.F) { Nav("Findings"); E<TextBox>("SearchBox").Focus(); E<TextBox>("SearchBox").SelectAll(); e.Handled = true; return; }
                if (e.Key == Key.Enter && Vm.CanStart && pages["Scan"].Visibility == Visibility.Visible && Vm.ShowSetup) { StartScan(); e.Handled = true; return; }
                if (e.Key == Key.O) { OpenScanFolder(); e.Handled = true; return; }
            }
            if (e.Key == Key.F5 && pages["History"].Visibility == Visibility.Visible) { RefreshHistory(false); e.Handled = true; }
            if (e.Key == Key.Escape && pages["Findings"].Visibility == Visibility.Visible && Vm.Search.Length > 0) { Vm.Search = ""; e.Handled = true; }
        }

        public void Nav(string page)
        {
            E<RadioButton>("Nav" + page).IsChecked = true;
        }

        void ShowPage(string page)
        {
            foreach (var kv in pages)
                kv.Value.Visibility = kv.Key == page ? Visibility.Visible : Visibility.Collapsed;
        }

        // =====================================================================
        // Scanning
        // =====================================================================
        void StartScan()
        {
            if (Vm.IsRunning || !Vm.CanStart) return;
            try { Directory.CreateDirectory(Vm.OutputRoot); }
            catch (Exception ex)
            {
                MessageBox.Show(this, "Can't write to " + Vm.OutputRoot + "\n\n" + ex.Message, "Triage Toolkit", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var opts = new ScanOptions
            {
                Modules = Vm.Modules.Where(m => m.IsSelected).Select(m => m.Number).ToList(),
                NetMinutes = Vm.NetMinutes,
                OutputRoot = Vm.OutputRoot,
            };

            foreach (var m in Vm.Modules) { m.Reset(); m.CanToggle = false; }
            console.Document.Blocks.Clear();
            consoleLines = 0;
            Vm.LiveRed = Vm.LiveYellow = Vm.LiveGreen = Vm.LiveInfo = 0;
            Vm.Progress = 0;
            Vm.StageText = "Preparing…";
            Vm.ScanFinished = false;
            Vm.IsRunning = true;
            scanStarted = DateTime.Now;
            currentRun = null;
            TaskbarItemInfo.ProgressState = TaskbarItemProgressState.Normal;
            TaskbarItemInfo.ProgressValue = 0;

            engine = new ScanEngine();
            engine.Log += (text, kind) => logQueue.Enqueue(new KeyValuePair<string, LogKind>(text, kind));
            engine.ModuleStarted += run => Dispatcher.BeginInvoke((Action)(() => OnModuleStarted(run)));
            engine.ModuleFinished += run => Dispatcher.BeginInvoke((Action)(() => OnModuleFinished(run)));
            engine.ModuleProgress += (run, p) => Dispatcher.BeginInvoke((Action)(() => { if (run == currentRun) currentFraction = p; }));

            var eng = engine;
            var worker = new Thread(() =>
            {
                var result = eng.Run(opts);
                Dispatcher.BeginInvoke((Action)(() => OnScanFinished(result)));
            });
            worker.IsBackground = true;
            worker.Name = "scan";
            worker.Start();
        }

        void CancelScan()
        {
            if (engine == null || !Vm.IsRunning) return;
            Vm.StageText = "Cancelling…";
            var eng = engine;
            ThreadPool.QueueUserWorkItem(_ => eng.Cancel());
        }

        void OnModuleStarted(ModuleRun run)
        {
            currentRun = run;
            currentStarted = DateTime.Now;
            currentFraction = -1;
            var vm = ModuleVm(run.Def.Number);
            vm.State = ModuleOutcome.Running;
            int pos = Vm.Modules.Where(m => m.IsSelected).ToList().IndexOf(vm) + 1;
            Vm.StageText = string.Format(CultureInfo.CurrentCulture, "Module {0} of {1}  ·  {2}", pos, Vm.SelectedCount, run.Def.Name);
        }

        void OnModuleFinished(ModuleRun run)
        {
            var vm = ModuleVm(run.Def.Number);
            vm.State = run.Outcome;
            vm.ElapsedText = Format.Duration(run.Elapsed);
            if (run.Result != null)
            {
                vm.ShowResult(run.Result);
                Vm.LiveRed += run.Result.Red;
                Vm.LiveYellow += run.Result.Yellow;
                Vm.LiveGreen += run.Result.Green;
                Vm.LiveInfo += run.Result.Info;
            }
            if (currentRun == run) currentRun = null;
        }

        void OnScanFinished(ScanResult result)
        {
            FlushLog();
            Vm.IsRunning = false;
            Vm.ScanFinished = true;
            Vm.Progress = 100;
            foreach (var m in Vm.Modules) m.CanToggle = true;
            engine = null;
            var elapsed = result.Finished - result.Started;

            bool loaded = false;
            if (ScanLoader.LooksLikeScanFolder(result.ReportDir))
            {
                LoadScan(result.ReportDir);
                loaded = true;
            }

            var icon = E<TextBlock>("DoneIcon");
            if (result.Error != null)
            {
                Vm.DoneTitle = "Scan stopped";
                Vm.DoneText = result.Error;
                icon.Text = ""; icon.Foreground = Palette.Fg(Severity.Red);
                TaskbarItemInfo.ProgressState = TaskbarItemProgressState.Error;
            }
            else if (result.Cancelled)
            {
                Vm.DoneTitle = "Scan cancelled";
                Vm.DoneText = loaded
                    ? "Results from the " + Format.Plural(result.Completed, "module that finished are", "modules that finished are") + " saved and open in Findings."
                    : "No module finished, so there is nothing to show.";
                icon.Text = ""; icon.Foreground = Palette.Fg(Severity.Yellow);
                TaskbarItemInfo.ProgressState = TaskbarItemProgressState.Paused;
            }
            else
            {
                var v = Vm.Scan != null ? Verdict.For(Vm.Scan.Red, Vm.Scan.Yellow) : null;
                int failed = result.Runs.Count(r => r.Outcome == ModuleOutcome.Failed || r.Outcome == ModuleOutcome.TimedOut);
                Vm.DoneTitle = v != null ? v.Title : "Scan complete";
                Vm.DoneText = "Finished in " + Format.Duration(elapsed) + "." +
                              (failed > 0 ? " " + Format.Plural(failed, "module", "modules") + " did not finish -- see Live output." : "") +
                              " Reports are saved in the scan folder.";
                icon.Text = v == null ? "" : v.Icon;
                icon.Foreground = v == null ? Palette.Fg(Severity.Green) : Palette.Fg(v.Css == "red" ? Severity.Red : v.Css == "yellow" ? Severity.Yellow : Severity.Green);
                TaskbarItemInfo.ProgressState = TaskbarItemProgressState.None;
            }
            Vm.StageText = "";
            RefreshHistory(false);
            if (!IsActive) Native.FlashUntilFocused(new WindowInteropHelper(this).Handle);
        }

        ModuleVM ModuleVm(string number)
        {
            return Vm.Modules.First(m => m.Number == number);
        }

        void OnTick()
        {
            FlushLog();
            if (!Vm.IsRunning) return;

            var now = DateTime.Now;
            Vm.TimeText = Format.Duration(now - scanStarted);

            // weighted progress across selected modules, by their time estimates
            var sel = Vm.Modules.Where(m => m.IsSelected).ToList();
            double total = Math.Max(1, sel.Sum(m => m.EstimateSeconds));
            double done = sel.Where(m => m.State != ModuleOutcome.Pending && m.State != ModuleOutcome.Running).Sum(m => m.EstimateSeconds);
            if (currentRun != null)
            {
                var vm = ModuleVm(currentRun.Def.Number);
                var el = now - currentStarted;
                vm.ElapsedText = Format.Duration(el);
                double frac = currentFraction >= 0 ? currentFraction : Math.Min(0.95, el.TotalSeconds / Math.Max(1, vm.EstimateSeconds));
                done += frac * vm.EstimateSeconds;
            }
            double pct = Math.Min(99, done / total * 100);
            if (pct > Vm.Progress) Vm.Progress = pct;
            TaskbarItemInfo.ProgressValue = Vm.Progress / 100.0;
        }

        // =====================================================================
        // Live output
        // =====================================================================
        void FlushLog()
        {
            if (logQueue.IsEmpty) return;
            var para = console.Document.Blocks.LastBlock as Paragraph;
            if (para == null) { para = new Paragraph(); console.Document.Blocks.Add(para); }
            string last = null;
            KeyValuePair<string, LogKind> item;
            int n = 0;
            while (n++ < 2000 && logQueue.TryDequeue(out item))
            {
                if (consoleLines > 0) para.Inlines.Add(new LineBreak());
                var run = new Run(item.Key) { Foreground = LogBrush(item.Value) };
                if (item.Value == LogKind.Heading) run.FontWeight = FontWeights.SemiBold;
                para.Inlines.Add(run);
                consoleLines++;
                if (!string.IsNullOrWhiteSpace(item.Key)) last = item.Key.Trim();
            }
            // keep the document bounded; modules can be chatty
            if (consoleLines > 6000)
            {
                while (para.Inlines.Count > 8000) para.Inlines.Remove(para.Inlines.FirstInline);
                consoleLines = para.Inlines.Count / 2;
            }
            if (last != null) E<TextBlock>("LastLine").Text = last;
            if (E<Border>("ConsoleHost").Visibility == Visibility.Visible) console.ScrollToEnd();
        }

        static Brush LogBrush(LogKind k)
        {
            switch (k)
            {
                case LogKind.Heading: return Palette.Accent;
                case LogKind.Good: return Palette.Fg(Severity.Green);
                case LogKind.Warn: return Palette.Fg(Severity.Yellow);
                case LogKind.Error: return Palette.Fg(Severity.Red);
                default: return Palette.Muted;
            }
        }

        public void FreezeForDocs() { tick.Stop(); }

        // Docs screenshots must not show the build machine's name or paths.
        public void MaskForDocs(string host, string realRoot, string fakeRoot)
        {
            Vm.MachineName = host;
            Vm.OutputRoot = fakeRoot;
            var items = Vm.History.ToList();
            Vm.History.Clear();
            foreach (var h in items)
            {
                h.Folder = fakeRoot + h.Folder.Substring(realRoot.Length);
                Vm.History.Add(h);
            }
            E<TextBlock>("HistSubtitle").Text = "Scans saved under " + fakeRoot + ".";
        }

        public void AppendLogForDocs(string text, LogKind kind)
        {
            logQueue.Enqueue(new KeyValuePair<string, LogKind>(text, kind));
            FlushLog();
        }

        // =====================================================================
        // Loading scans
        // =====================================================================
        public void LoadScan(string folder)
        {
            LoadedScan scan;
            try { scan = ScanLoader.Load(folder); }
            catch (Exception ex)
            {
                MessageBox.Show(this, "Couldn't read that scan.\n\n" + ex.Message, "Triage Toolkit", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            if (scan.Modules.Count == 0)
            {
                MessageBox.Show(this, "No module results (NN_*.json) were found in\n" + folder, "Triage Toolkit", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            // Baseline: the most recent earlier scan of the same host we know about.
            HashSet<string> baseKeys = null;
            var baseline = Vm.History
                .Where(h => string.Equals(h.Hostname, scan.Hostname, StringComparison.OrdinalIgnoreCase) &&
                            h.Started < scan.Started && !SameFolder(h.Folder, folder))
                .OrderByDescending(h => h.Started).FirstOrDefault();
            if (baseline != null)
            {
                try { baseKeys = new HashSet<string>(ScanLoader.Load(baseline.Folder).AllFindings.Select(f => f.Key)); }
                catch { baseKeys = null; }
            }

            var vms = scan.Modules
                .SelectMany(m => m.Findings.Select(f => new FindingVM(f, m.HtmlPath,
                    baseKeys != null && (f.Severity == Severity.Red || f.Severity == Severity.Yellow) && !baseKeys.Contains(f.Key))))
                .OrderBy(f => f.Rank).ThenBy(f => f.ModuleNumber).ThenBy(f => f.Title, StringComparer.CurrentCultureIgnoreCase)
                .ToList();

            Vm.Selected = null;
            Vm.Findings.Clear();
            foreach (var f in vms) Vm.Findings.Add(f);

            Vm.ModuleFilters.Clear();
            var all = new ModuleFilterItem { Number = null, Label = "All modules" };
            Vm.ModuleFilters.Add(all);
            foreach (var m in scan.Modules.OrderBy(m => m.Module))
            {
                int n = m.Red + m.Yellow;
                Vm.ModuleFilters.Add(new ModuleFilterItem { Number = m.Module, Label = m.Module + "  " + m.Title + (n > 0 ? "  (" + n + ")" : "") });
            }
            Vm.ModuleFilter = all;

            Vm.HasBaseline = baseKeys != null;
            int newCount = vms.Count(f => f.IsNew);
            Vm.BaselineText = baseline == null ? "" :
                "Compared with the scan from " + baseline.Started.ToString("d MMM yyyy HH:mm", CultureInfo.CurrentCulture) +
                ": " + Format.Plural(newCount, "new critical/warning finding", "new critical/warning findings");
            if (!Vm.HasBaseline) Vm.OnlyNew = false;

            Vm.Scan = scan;
            Vm.ManifestText = File.Exists(scan.ManifestPath)
                ? "manifest.json records the SHA-256 of every report file. Verify re-hashes the folder to show nothing was altered after the scan."
                : "This scan has no manifest.json (scans from v2.0 onward write one), so it can't be verified.";
            Vm.Refilter();

            if (!Vm.History.Any(h => SameFolder(h.Folder, folder))) extraFolders.Add(folder);
            foreach (var h in Vm.History) h.IsCurrent = SameFolder(h.Folder, folder);
        }

        static bool SameFolder(string a, string b)
        {
            return string.Equals(Path.GetFullPath(a).TrimEnd('\\'), Path.GetFullPath(b).TrimEnd('\\'), StringComparison.OrdinalIgnoreCase);
        }

        void OpenScanFolder()
        {
            string start = Vm.Scan != null ? Path.GetDirectoryName(Vm.Scan.Folder) : Vm.OutputRoot;
            string dir = Native.PickFolder(new WindowInteropHelper(this).Handle, "Open a scan folder", start);
            if (dir == null) return;
            if (!ScanLoader.LooksLikeScanFolder(dir))
            {
                // Allow picking a host folder or Logs root: take the newest scan under it.
                var inner = HistoryStore.Discover(dir).OrderByDescending(h => h.Item2).FirstOrDefault();
                if (inner == null)
                {
                    MessageBox.Show(this, "That folder doesn't contain a triage scan (no NN_*.json module results).", "Triage Toolkit", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }
                dir = inner.Item1;
            }
            extraFolders.Add(dir);
            RefreshHistory(false);
            LoadScan(dir);
            Nav("Findings");
        }

        // =====================================================================
        // History
        // =====================================================================
        public void RefreshHistory(bool openNewest)
        {
            string rootDir = Vm.OutputRoot;
            var extras = extraFolders.ToList();
            string current = Vm.Scan != null ? Vm.Scan.Folder : null;
            Task.Factory.StartNew(() => HistoryStore.Load(rootDir, extras)).ContinueWith(t =>
            {
                if (t.IsFaulted) return;
                Vm.History.Clear();
                foreach (var h in t.Result)
                {
                    string folder = h.Folder;
                    h.OpenCommand = new RelayCommand(_ => { LoadScan(folder); Nav("Findings"); });
                    h.FolderCommand = new RelayCommand(_ => ShellOpen(folder));
                    h.IsCurrent = current != null && SameFolder(folder, current);
                    Vm.History.Add(h);
                }
                E<TextBlock>("HistSubtitle").Text = "Scans saved under " + rootDir + (extras.Count > 0 ? ", plus folders you opened this session." : ".");
                E<FrameworkElement>("HistEmpty").Visibility = Vm.History.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
                if (openNewest && Vm.Scan == null && Vm.History.Count > 0)
                    LoadScan(Vm.History[0].Folder);
            }, TaskScheduler.FromCurrentSynchronizationContext());
        }

        void ChangeOutputRoot()
        {
            string dir = Native.PickFolder(new WindowInteropHelper(this).Handle, "Save reports to", Vm.OutputRoot);
            if (dir == null) return;
            Vm.OutputRoot = dir;
            RefreshHistory(false);
        }

        // =====================================================================
        // Export
        // =====================================================================
        void SaveExport()
        {
            if (!Vm.HasExport) { Toast("This scan has no hand-off summary"); return; }
            var dlg = new Microsoft.Win32.SaveFileDialog
            {
                FileName = Vm.Scan.Hostname + "_triage_summary.txt",
                Filter = "Text file (*.txt)|*.txt",
            };
            if (dlg.ShowDialog(this) != true) return;
            File.Copy(Vm.Scan.ExportText, dlg.FileName, true);
            Toast("Saved " + Path.GetFileName(dlg.FileName));
        }

        void SaveCsv()
        {
            if (Vm.Scan == null) return;
            var dlg = new Microsoft.Win32.SaveFileDialog
            {
                FileName = Vm.Scan.Hostname + "_findings_" + Vm.Scan.Started.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) + ".csv",
                Filter = "CSV (*.csv)|*.csv",
            };
            if (dlg.ShowDialog(this) != true) return;
            try
            {
                ReportWriter.WriteCsv(Vm.Findings.Select(f => f.F), dlg.FileName);
                Toast("Exported " + Format.Plural(Vm.Findings.Count, "finding", "findings"));
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Export failed", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        void VerifyManifest()
        {
            if (Vm.Scan == null) return;
            Tuple<bool, int, List<string>> r;
            try { r = ReportWriter.VerifyManifest(Vm.Scan.Folder); }
            catch (Exception ex) { Vm.ManifestText = "Couldn't read manifest.json: " + ex.Message; return; }
            if (r == null) { Toast("No manifest.json in this scan"); return; }
            Vm.ManifestText = r.Item1
                ? "Verified " + DateTime.Now.ToString("HH:mm", CultureInfo.CurrentCulture) + ": all " + r.Item2 + " files match their recorded SHA-256."
                : "Mismatch: " + string.Join(", ", r.Item3) + " changed or missing since the scan.";
            Toast(r.Item1 ? "All " + r.Item2 + " files verified" : Format.Plural(r.Item3.Count, "file differs", "files differ"));
        }

        void OpenSummaryHtml()
        {
            if (Vm.Scan == null) return;
            if (!File.Exists(Vm.Scan.SummaryHtml))
            {
                // scans from before v2.0 have no summary page; write one (only touches the scan folder)
                try { ReportWriter.WriteSummaryHtml(Vm.Scan); }
                catch { }
            }
            if (File.Exists(Vm.Scan.SummaryHtml)) ShellOpen(Vm.Scan.SummaryHtml);
            else ShellOpen(Vm.Scan.Folder);
        }

        // =====================================================================
        // Misc
        // =====================================================================
        void VerifyIntegrity()
        {
            var results = ScanEngine.VerifyEmbeddedScripts();
            foreach (var r in results) Vm.Integrity.Add(r);
            int ok = results.Count(r => r.Value);
            Vm.IntegrityOk = ok == results.Count;
            Vm.IntegrityText = Vm.IntegrityOk ? "All " + ok + " scripts verified" : (results.Count - ok) + " scripts failed verification";
            if (!Vm.IntegrityOk)
            {
                var ic = E<TextBlock>("IntegrityIcon");
                ic.Text = "";
                ic.Foreground = Palette.Fg(Severity.Red);
            }
        }

        // Opens files, folders and URLs through Explorer so they run un-elevated in the
        // user's session -- a browser launched directly from this admin process would
        // itself run as administrator.
        static void ShellOpen(string target)
        {
            try
            {
                string explorer = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe");
                Process.Start(new ProcessStartInfo(explorer, "\"" + target + "\"") { UseShellExecute = false });
            }
            catch { }
        }

        void CopyText(string text, string message)
        {
            for (int i = 0; i < 5; i++)
            {
                try { Clipboard.SetText(text ?? ""); Toast(message); return; }
                catch { Thread.Sleep(40); }   // clipboard briefly locked by another app
            }
            Toast("Clipboard is busy -- try again");
        }

        public void Toast(string text)
        {
            E<TextBlock>("ToastText").Text = text;
            var t = E<Border>("Toast");
            var a = new DoubleAnimationUsingKeyFrames();
            a.KeyFrames.Add(new EasingDoubleKeyFrame(1, KeyTime.FromTimeSpan(TimeSpan.FromMilliseconds(160))));
            a.KeyFrames.Add(new EasingDoubleKeyFrame(1, KeyTime.FromTimeSpan(TimeSpan.FromMilliseconds(1900))));
            a.KeyFrames.Add(new EasingDoubleKeyFrame(0, KeyTime.FromTimeSpan(TimeSpan.FromMilliseconds(2300))));
            t.BeginAnimation(OpacityProperty, a);
        }

        protected override void OnClosing(CancelEventArgs e)
        {
            if (Vm.IsRunning)
            {
                var r = MessageBox.Show(this, "A scan is still running. Stop it and close?\n\nModules that already finished keep their reports.",
                    "Triage Toolkit", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No);
                if (r != MessageBoxResult.Yes) { e.Cancel = true; return; }
                if (engine != null) engine.Cancel();
            }
            base.OnClosing(e);
        }
    }
}
