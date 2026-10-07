// =============================================================================
// ViewModels.cs -- bindable state behind MainWindow.xaml
// =============================================================================

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;

namespace TriageToolkit
{
    public abstract class Observable : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        protected bool Set<T>(ref T field, T value, [CallerMemberName] string name = null)
        {
            if (EqualityComparer<T>.Default.Equals(field, value)) return false;
            field = value;
            Raise(name);
            return true;
        }

        protected void Raise(string name)
        {
            var h = PropertyChanged;
            if (h != null) h(this, new PropertyChangedEventArgs(name));
        }
    }

    public sealed class RelayCommand : ICommand
    {
        readonly Action<object> run;
        public RelayCommand(Action<object> run) { this.run = run; }
        public event EventHandler CanExecuteChanged { add { } remove { } }
        public bool CanExecute(object p) { return true; }
        public void Execute(object p) { run(p); }
    }

    public static class Palette
    {
        static Brush B(string key) { return (Brush)Application.Current.Resources[key]; }

        public static Brush Fg(string sev)
        {
            switch (Severity.Normalize(sev))
            {
                case Severity.Red: return B("Red");
                case Severity.Yellow: return B("Yellow");
                case Severity.Green: return B("Green");
                default: return B("Info");
            }
        }

        public static Brush Soft(string sev)
        {
            switch (Severity.Normalize(sev))
            {
                case Severity.Red: return B("RedSoft");
                case Severity.Yellow: return B("YellowSoft");
                case Severity.Green: return B("GreenSoft");
                default: return B("InfoSoft");
            }
        }

        public static Brush Muted { get { return B("Muted"); } }
        public static Brush Subtle { get { return B("Subtle"); } }
        public static Brush Accent { get { return B("Accent"); } }
    }

    // -------------------------------------------------------------------------
    // Scan page: one row per module
    // -------------------------------------------------------------------------
    public sealed class ModuleVM : Observable
    {
        public ModuleDef Def { get; private set; }
        readonly Func<int> netMinutes;

        public ModuleVM(ModuleDef def, Func<int> netMinutes)
        {
            Def = def;
            this.netMinutes = netMinutes;
        }

        public string Number { get { return Def.Number; } }
        public string Name { get { return Def.Name; } }
        public string Description { get { return Def.Description; } }

        public int EstimateSeconds
        {
            get { return Def.IsNetworkWatch ? netMinutes() * 60 + 30 : Def.EstimateSeconds; }
        }
        public string EstimateText { get { return Format.Minutes(EstimateSeconds); } }
        public void RefreshEstimate() { Raise("EstimateText"); }

        bool isSelected = true;
        public bool IsSelected { get { return isSelected; } set { Set(ref isSelected, value); } }

        bool canToggle = true;
        public bool CanToggle { get { return canToggle; } set { Set(ref canToggle, value); } }

        ModuleOutcome state = ModuleOutcome.Pending;
        public ModuleOutcome State
        {
            get { return state; }
            set
            {
                if (!Set(ref state, value)) return;
                Raise("IsRunning"); Raise("IsIdle"); Raise("HasResult"); Raise("HasProblem");
                Raise("ProblemText"); Raise("StateIcon"); Raise("StateBrush");
            }
        }

        public bool IsRunning { get { return state == ModuleOutcome.Running; } }
        public bool IsIdle { get { return state == ModuleOutcome.Pending; } }
        public bool HasResult { get { return state == ModuleOutcome.Completed; } }
        public bool HasProblem
        {
            get { return state == ModuleOutcome.Failed || state == ModuleOutcome.TimedOut || state == ModuleOutcome.Cancelled || state == ModuleOutcome.Skipped; }
        }

        public string ProblemText
        {
            get
            {
                switch (state)
                {
                    case ModuleOutcome.Failed: return "Failed";
                    case ModuleOutcome.TimedOut: return "Timed out";
                    case ModuleOutcome.Cancelled: return "Cancelled";
                    case ModuleOutcome.Skipped: return "Skipped";
                    default: return "";
                }
            }
        }

        public string StateIcon
        {
            get
            {
                switch (state)
                {
                    case ModuleOutcome.Completed: return "";     // check
                    case ModuleOutcome.Failed:
                    case ModuleOutcome.TimedOut: return "";      // error
                    case ModuleOutcome.Cancelled:
                    case ModuleOutcome.Skipped: return "";       // dash
                    default: return "";
                }
            }
        }

        public Brush StateBrush
        {
            get
            {
                switch (state)
                {
                    case ModuleOutcome.Completed: return Palette.Fg(Severity.Green);
                    case ModuleOutcome.Failed:
                    case ModuleOutcome.TimedOut: return Palette.Fg(Severity.Red);
                    default: return Palette.Subtle;
                }
            }
        }

        string elapsedText = "";
        public string ElapsedText { get { return elapsedText; } set { Set(ref elapsedText, value); } }

        string resultText = "";
        public string ResultText { get { return resultText; } set { Set(ref resultText, value); } }

        Brush resultBrush;
        public Brush ResultBrush { get { return resultBrush; } set { Set(ref resultBrush, value); } }

        Brush resultSoft;
        public Brush ResultSoft { get { return resultSoft; } set { Set(ref resultSoft, value); } }

        public void ShowResult(ModuleResult r)
        {
            if (r == null) return;
            string sev = r.Red > 0 ? Severity.Red : r.Yellow > 0 ? Severity.Yellow : Severity.Green;
            ResultText = r.Red > 0 ? Format.Plural(r.Red, "critical", "critical")
                       : r.Yellow > 0 ? Format.Plural(r.Yellow, "warning", "warnings")
                       : "Clean";
            ResultBrush = Palette.Fg(sev);
            ResultSoft = Palette.Soft(sev);
        }

        public void Reset()
        {
            State = ModuleOutcome.Pending;
            ElapsedText = "";
            ResultText = "";
        }
    }

    // -------------------------------------------------------------------------
    // Findings page
    // -------------------------------------------------------------------------
    public sealed class FindingVM : Observable
    {
        public Finding F { get; private set; }
        public string HtmlPath { get; private set; }

        public FindingVM(Finding f, string htmlPath, bool isNew)
        {
            F = f;
            HtmlPath = htmlPath;
            IsNew = isNew;
        }

        public string Severity { get { return F.Severity; } }
        public string SeverityLabel { get { return TriageToolkit.Severity.Label(F.Severity); } }
        public int Rank { get { return TriageToolkit.Severity.Rank(F.Severity); } }
        public Brush SeverityBrush { get { return Palette.Fg(F.Severity); } }
        public Brush SeveritySoft { get { return Palette.Soft(F.Severity); } }
        public string Title { get { return F.Title; } }
        public string Detail { get { return F.Detail; } }
        public string WhyItMatters { get { return F.WhyItMatters; } }
        public string WhyMightBeNormal { get { return F.WhyMightBeNormal; } }
        public bool HasDetail { get { return !string.IsNullOrWhiteSpace(F.Detail); } }
        public bool HasWhy { get { return !string.IsNullOrWhiteSpace(F.WhyItMatters); } }
        public bool HasNormal { get { return !string.IsNullOrWhiteSpace(F.WhyMightBeNormal); } }
        public string ModuleNumber { get { return F.ModuleNumber; } }
        public string ModuleLabel { get { return F.ModuleNumber + "  " + F.ModuleTitle; } }
        public bool HasReport { get { return !string.IsNullOrEmpty(HtmlPath); } }
        public bool IsNew { get; private set; }

        public string MetaText
        {
            get
            {
                var parts = new List<string>();
                if (!string.IsNullOrWhiteSpace(F.CreatedDate)) parts.Add("Created " + F.CreatedDate);
                if (!string.IsNullOrWhiteSpace(F.Sid)) parts.Add("SID " + F.Sid);
                return string.Join("    ", parts);
            }
        }
        public bool HasMeta { get { return MetaText.Length > 0; } }

        public string AsText()
        {
            var lines = new List<string>
            {
                "[" + F.Severity + "] " + F.Title,
                "Module: " + ModuleLabel,
            };
            if (HasDetail) lines.Add("Detail: " + F.Detail);
            if (HasWhy) lines.Add("Why it matters: " + F.WhyItMatters);
            if (HasNormal) lines.Add("May be normal: " + F.WhyMightBeNormal);
            if (HasMeta) lines.Add(MetaText);
            return string.Join(Environment.NewLine, lines);
        }
    }

    public sealed class ModuleFilterItem
    {
        public string Number;   // null = all
        public string Label { get; set; }
        public override string ToString() { return Label; }
    }

    // -------------------------------------------------------------------------
    // History page
    // -------------------------------------------------------------------------
    public sealed class HistoryItemVM : Observable
    {
        public string Folder { get; set; }
        public string Hostname { get; set; }
        public DateTime Started { get; set; }
        public int Red { get; set; }
        public int Yellow { get; set; }
        public int Green { get; set; }
        public int Info { get; set; }
        public int ModuleCount { get; set; }
        bool isCurrent;
        public bool IsCurrent { get { return isCurrent; } set { Set(ref isCurrent, value); } }
        public ICommand OpenCommand { get; set; }
        public ICommand FolderCommand { get; set; }

        public string DateText { get { return Started.ToString("ddd d MMM yyyy", CultureInfo.CurrentCulture); } }
        public string TimeText { get { return Started.ToString("HH:mm", CultureInfo.CurrentCulture); } }
        public string ModulesText { get { return Format.Plural(ModuleCount, "module", "modules"); } }
        public bool HasRed { get { return Red > 0; } }
        public bool HasYellow { get { return Yellow > 0; } }
        public bool AllClear { get { return Red == 0 && Yellow == 0; } }
    }

    // -------------------------------------------------------------------------
    // Main window state
    // -------------------------------------------------------------------------
    public sealed class MainViewModel : Observable
    {
        public ObservableCollection<ModuleVM> Modules { get; private set; }
        public ObservableCollection<FindingVM> Findings { get; private set; }
        public ObservableCollection<ModuleFilterItem> ModuleFilters { get; private set; }
        public ObservableCollection<HistoryItemVM> History { get; private set; }
        public ObservableCollection<KeyValuePair<string, bool>> Integrity { get; private set; }
        public ICollectionView FindingsView { get; private set; }

        public MainViewModel()
        {
            Modules = new ObservableCollection<ModuleVM>(ModuleCatalog.All.Select(d => new ModuleVM(d, () => NetMinutes)));
            Findings = new ObservableCollection<FindingVM>();
            ModuleFilters = new ObservableCollection<ModuleFilterItem>();
            History = new ObservableCollection<HistoryItemVM>();
            Integrity = new ObservableCollection<KeyValuePair<string, bool>>();
            FindingsView = CollectionViewSource.GetDefaultView(Findings);
            FindingsView.Filter = o => PassesFilter((FindingVM)o);
            foreach (var m in Modules) m.PropertyChanged += (s, e) => { if (e.PropertyName == "IsSelected") RaiseEstimate(); };
        }

        // ----- machine -----
        string machineName = Environment.MachineName;
        public string MachineName { get { return machineName; } set { Set(ref machineName, value); } }
        public string Version { get { return "v" + BuildInfo.Version; } }
        public string VersionLong { get { return "Version " + BuildInfo.Version + "  ·  built " + BuildInfo.BuildDate; } }
        public bool IsAdmin { get; set; }
        public string AdminText { get { return IsAdmin ? "Administrator" : "Standard user — results will be incomplete"; } }
        public Brush AdminBrush { get { return IsAdmin ? Palette.Fg(Severity.Green) : Palette.Fg(Severity.Yellow); } }

        string integrityText = "";
        public string IntegrityText { get { return integrityText; } set { Set(ref integrityText, value); } }
        bool integrityOk;
        public bool IntegrityOk { get { return integrityOk; } set { Set(ref integrityOk, value); } }

        // ----- scan setup -----
        int netMinutes = 5;
        public int NetMinutes
        {
            get { return netMinutes; }
            set { if (Set(ref netMinutes, value)) { foreach (var m in Modules) m.RefreshEstimate(); RaiseEstimate(); } }
        }

        string outputRoot = "";
        public string OutputRoot { get { return outputRoot; } set { Set(ref outputRoot, value); } }

        public int SelectedCount { get { return Modules.Count(m => m.IsSelected); } }
        public string EstimateText
        {
            get
            {
                int secs = Modules.Where(m => m.IsSelected).Sum(m => m.EstimateSeconds);
                if (SelectedCount == 0) return "Choose at least one module";
                return Format.Plural(SelectedCount, "module", "modules") + "  ·  about " +
                       Math.Max(1, (int)Math.Round(secs / 60.0)) + " min";
            }
        }
        public bool CanStart { get { return SelectedCount > 0 && !IsRunning; } }
        void RaiseEstimate() { Raise("EstimateText"); Raise("SelectedCount"); Raise("CanStart"); }

        // ----- scan running -----
        bool isRunning;
        public bool IsRunning
        {
            get { return isRunning; }
            set { if (Set(ref isRunning, value)) { Raise("IsNotRunning"); Raise("CanStart"); Raise("ShowSetup"); Raise("ShowProgress"); Raise("ShowDone"); } }
        }
        public bool IsNotRunning { get { return !isRunning; } }

        bool scanFinished;
        public bool ScanFinished
        {
            get { return scanFinished; }
            set { if (Set(ref scanFinished, value)) { Raise("ShowSetup"); Raise("ShowDone"); } }
        }
        public bool ShowSetup { get { return !isRunning && !scanFinished; } }
        public bool ShowProgress { get { return isRunning; } }
        public bool ShowDone { get { return !isRunning && scanFinished; } }

        double progress;
        public double Progress { get { return progress; } set { if (Set(ref progress, value)) Raise("ProgressText"); } }
        public string ProgressText { get { return ((int)Math.Floor(progress)).ToString(CultureInfo.InvariantCulture) + "%"; } }

        string stageText = "";
        public string StageText { get { return stageText; } set { Set(ref stageText, value); } }
        string timeText = "";
        public string TimeText { get { return timeText; } set { Set(ref timeText, value); } }
        string doneTitle = "";
        public string DoneTitle { get { return doneTitle; } set { Set(ref doneTitle, value); } }
        string doneText = "";
        public string DoneText { get { return doneText; } set { Set(ref doneText, value); } }
        bool doneOk;
        public bool DoneOk { get { return doneOk; } set { Set(ref doneOk, value); } }

        int liveRed, liveYellow, liveGreen, liveInfo;
        public int LiveRed { get { return liveRed; } set { Set(ref liveRed, value); } }
        public int LiveYellow { get { return liveYellow; } set { Set(ref liveYellow, value); } }
        public int LiveGreen { get { return liveGreen; } set { Set(ref liveGreen, value); } }
        public int LiveInfo { get { return liveInfo; } set { Set(ref liveInfo, value); } }

        // ----- loaded scan -----
        LoadedScan scan;
        public LoadedScan Scan
        {
            get { return scan; }
            set
            {
                scan = value;
                foreach (var n in new[] { "Scan", "HasScan", "NoScan", "ScanHost", "ScanWhen", "VerdictTitle", "VerdictText",
                                          "VerdictBrush", "VerdictSoft", "VerdictIcon", "Red", "Yellow", "Green", "Info",
                                          "HasSummaryHtml", "HasExport", "ExportPreview", "ManifestText" })
                    Raise(n);
            }
        }
        public bool HasScan { get { return scan != null; } }
        public bool NoScan { get { return scan == null; } }
        public string ScanHost { get { return scan == null ? "" : scan.Hostname; } }
        public string ScanWhen
        {
            get
            {
                if (scan == null) return "";
                var parts = new List<string> { "Scanned " + scan.Started.ToString("d MMM yyyy, HH:mm", CultureInfo.CurrentCulture) };
                parts.Add(Format.Plural(scan.Modules.Count, "module", "modules"));
                if (scan.Duration.HasValue) parts.Add(Format.Duration(scan.Duration.Value));
                if (!string.IsNullOrEmpty(scan.Version)) parts.Add("toolkit v" + scan.Version);
                return string.Join("  ·  ", parts);
            }
        }
        Verdict V { get { return scan == null ? null : Verdict.For(scan.Red, scan.Yellow); } }
        public string VerdictTitle { get { return V == null ? "" : V.Title; } }
        public string VerdictText { get { return V == null ? "" : V.Subtitle; } }
        public string VerdictIcon { get { return V == null ? "" : V.Icon; } }
        public Brush VerdictBrush { get { return V == null ? null : Palette.Fg(V.Css == "red" ? Severity.Red : V.Css == "yellow" ? Severity.Yellow : Severity.Green); } }
        public Brush VerdictSoft { get { return V == null ? null : Palette.Soft(V.Css == "red" ? Severity.Red : V.Css == "yellow" ? Severity.Yellow : Severity.Green); } }
        public int Red { get { return scan == null ? 0 : scan.Red; } }
        public int Yellow { get { return scan == null ? 0 : scan.Yellow; } }
        public int Green { get { return scan == null ? 0 : scan.Green; } }
        public int Info { get { return scan == null ? 0 : scan.Info; } }
        public bool HasSummaryHtml { get { return scan != null && System.IO.File.Exists(scan.SummaryHtml); } }
        public bool HasExport { get { return scan != null && System.IO.File.Exists(scan.ExportText); } }

        public string ExportPreview
        {
            get
            {
                if (scan == null) return "";
                try
                {
                    return System.IO.File.Exists(scan.ExportText)
                        ? System.IO.File.ReadAllText(scan.ExportText)
                        : "This scan has no hand-off summary. It is written by module 10 (Cross-Module Correlation) -- run a scan that includes it.";
                }
                catch (Exception ex) { return "Could not read the summary: " + ex.Message; }
            }
        }

        string manifestText = "";
        public string ManifestText { get { return manifestText; } set { Set(ref manifestText, value); } }

        // ----- filters -----
        bool showRed = true, showYellow = true, showGreen, showInfo;
        public bool ShowRed { get { return showRed; } set { if (Set(ref showRed, value)) Refilter(); } }
        public bool ShowYellow { get { return showYellow; } set { if (Set(ref showYellow, value)) Refilter(); } }
        public bool ShowGreen { get { return showGreen; } set { if (Set(ref showGreen, value)) Refilter(); } }
        public bool ShowInfo { get { return showInfo; } set { if (Set(ref showInfo, value)) Refilter(); } }

        string search = "";
        public string Search { get { return search; } set { if (Set(ref search, value ?? "")) Refilter(); } }

        ModuleFilterItem moduleFilter;
        public ModuleFilterItem ModuleFilter { get { return moduleFilter; } set { if (Set(ref moduleFilter, value)) Refilter(); } }

        bool onlyNew;
        public bool OnlyNew { get { return onlyNew; } set { if (Set(ref onlyNew, value)) Refilter(); } }

        bool hasBaseline;
        public bool HasBaseline { get { return hasBaseline; } set { Set(ref hasBaseline, value); } }
        string baselineText = "";
        public string BaselineText { get { return baselineText; } set { Set(ref baselineText, value); } }

        FindingVM selected;
        public FindingVM Selected { get { return selected; } set { if (Set(ref selected, value)) Raise("HasSelected"); } }
        public bool HasSelected { get { return selected != null; } }

        string shownText = "";
        public string ShownText { get { return shownText; } set { Set(ref shownText, value); } }
        public bool NothingShown { get { return HasScan && FindingsView.IsEmpty; } }

        bool PassesFilter(FindingVM f)
        {
            switch (f.Severity)
            {
                case Severity.Red: if (!showRed) return false; break;
                case Severity.Yellow: if (!showYellow) return false; break;
                case Severity.Green: if (!showGreen) return false; break;
                default: if (!showInfo) return false; break;
            }
            if (onlyNew && !f.IsNew) return false;
            if (moduleFilter != null && moduleFilter.Number != null && f.ModuleNumber != moduleFilter.Number) return false;
            if (search.Length > 0)
            {
                var c = CultureInfo.InvariantCulture.CompareInfo;
                var o = CompareOptions.IgnoreCase;
                if (c.IndexOf(f.Title ?? "", search, o) < 0 && c.IndexOf(f.Detail ?? "", search, o) < 0 &&
                    c.IndexOf(f.WhyItMatters ?? "", search, o) < 0 && c.IndexOf(f.ModuleLabel, search, o) < 0)
                    return false;
            }
            return true;
        }

        public void Refilter()
        {
            FindingsView.Refresh();
            int shown = FindingsView.Cast<object>().Count();
            ShownText = shown == Findings.Count
                ? Format.Plural(shown, "finding", "findings")
                : shown + " of " + Findings.Count + " findings";
            Raise("NothingShown");
            if (Selected != null && !PassesFilter(Selected)) Selected = null;
            if (Selected == null) Selected = FindingsView.Cast<FindingVM>().FirstOrDefault();
        }
    }
}
