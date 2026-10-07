// =============================================================================
// Models.cs -- module catalogue, scan data model, JSON loading
// =============================================================================
// The PowerShell modules each write NN_Title.json next to their HTML report
// (Write-ModuleJson in Common.ps1). Everything the app shows is read back from
// those files, so a scan folder copied off another machine opens the same way
// as one produced here.
// =============================================================================

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;

namespace TriageToolkit
{
    public sealed class ModuleDef
    {
        public string Number;
        public string File;
        public string Name;
        public string Description;
        public int EstimateSeconds;
        public bool IsNetworkWatch;
        public bool IsCorrelation;
    }

    public static class ModuleCatalog
    {
        public static readonly ModuleDef[] All =
        {
            M("01", "01_SystemIdentity.ps1",       "System Identity",          "Hardware, BIOS, OS build, install date, time zone", 20),
            M("02", "02_StorageAndFiles.ps1",      "Storage & Files",          "BitLocker, executables in user-writable paths, Prefetch, PowerShell history", 90),
            M("03", "03_SecurityConfig.ps1",       "Security Configuration",   "Defender, Secure Boot, TPM, UAC, LSASS protection, firewall, VBS", 30),
            M("04", "04_AccountsAndAuth.ps1",      "Accounts & Authentication","Local accounts, admin group, RDP history, failed logons, password policy", 40),
            M("05", "05_ProcessesAndSoftware.ps1", "Processes & Software",     "Running processes, remote-access tools, unsigned binaries, installs", 90),
            M("06", "06_Persistence.ps1",          "Persistence Mechanisms",   "Run keys, Winlogon, scheduled tasks, services, WMI subscriptions, IFEO", 90),
            M("07", "07_NetworkSnapshot.ps1",      "Network Snapshot",         "DNS, hosts file, listening ports, shares, proxy, ARP", 30),
            M("08", "08_NetworkTimeSeries.ps1",    "Network Time Series",      "Watches live connections for persistent beacons, then reverse-DNS", 330),
            M("09", "09_ForensicArtifacts.ps1",    "Forensic Artifacts",       "USB history, Security log analysis, crash dumps, archives, browsers", 60),
            M("10", "10_Correlation.ps1",          "Cross-Module Correlation", "Joins every module's findings to explain noise and surface patterns", 15),
        };

        static ModuleDef M(string num, string file, string name, string desc, int est)
        {
            return new ModuleDef
            {
                Number = num, File = file, Name = name, Description = desc, EstimateSeconds = est,
                IsNetworkWatch = num == "08", IsCorrelation = num == "10"
            };
        }

        public static ModuleDef ByNumber(string num)
        {
            return All.FirstOrDefault(m => m.Number == num);
        }

        public static string[] ScriptResources
        {
            get { return new[] { "Common.ps1" }.Concat(All.Select(m => m.File)).ToArray(); }
        }
    }

    public static class Severity
    {
        public const string Red = "RED", Yellow = "YELLOW", Green = "GREEN", Info = "INFO";

        public static int Rank(string sev)
        {
            switch ((sev ?? "").ToUpperInvariant())
            {
                case Red: return 0;
                case Yellow: return 1;
                case Green: return 2;
                default: return 3;
            }
        }

        public static string Label(string sev)
        {
            switch ((sev ?? "").ToUpperInvariant())
            {
                case Red: return "Critical";
                case Yellow: return "Warning";
                case Green: return "Clean";
                default: return "Info";
            }
        }

        public static string Normalize(string sev)
        {
            string s = (sev ?? "").ToUpperInvariant();
            return s == Red || s == Yellow || s == Green ? s : Info;
        }
    }

    public sealed class Finding
    {
        public string Severity = "";
        public string Title = "";
        public string Detail = "";
        public string WhyItMatters = "";
        public string WhyMightBeNormal = "";
        public string CreatedDate = "";
        public string Sid = "";
        public string ModuleNumber = "";
        public string ModuleTitle = "";

        // Stable identity across scans of the same host, used for "new since last scan".
        public string Key
        {
            get { return ModuleNumber + "|" + Severity + "|" + Title; }
        }
    }

    public sealed class ModuleResult
    {
        public string Module = "";
        public string Title = "";
        public string Hostname = "";
        public string ScanTime = "";
        public string Version = "";
        public bool Admin;
        public string JsonPath = "";
        public string HtmlPath = "";
        public int Red, Yellow, Green, Info;
        public List<Finding> Findings = new List<Finding>();
    }

    public sealed class LoadedScan
    {
        public string Folder = "";
        public string Hostname = "";
        public DateTime Started;
        public TimeSpan? Duration;
        public string Version = "";
        public List<ModuleResult> Modules = new List<ModuleResult>();

        public IEnumerable<Finding> AllFindings { get { return Modules.SelectMany(m => m.Findings); } }
        public int Red { get { return Modules.Sum(m => m.Red); } }
        public int Yellow { get { return Modules.Sum(m => m.Yellow); } }
        public int Green { get { return Modules.Sum(m => m.Green); } }
        public int Info { get { return Modules.Sum(m => m.Info); } }

        public string SummaryHtml { get { return Path.Combine(Folder, "00_Summary.html"); } }
        public string ExportText { get { return Path.Combine(Folder, "10_Correlation_Export.txt"); } }
        public string ManifestPath { get { return Path.Combine(Folder, "manifest.json"); } }
    }

    // -------------------------------------------------------------------------
    // Reads a scan folder (NN_*.json from the modules, plus scan.json written by
    // the app when the scan ran through it).
    // -------------------------------------------------------------------------
    public static class ScanLoader
    {
        static readonly Regex ModuleJson = new Regex(@"^(\d{2})_.+\.json$", RegexOptions.IgnoreCase);
        static readonly Regex FolderStamp = new Regex(@"(\d{4}-\d{2}-\d{2})_(\d{2})-(\d{2})-(\d{2})");

        public static bool LooksLikeScanFolder(string dir)
        {
            try
            {
                return Directory.Exists(dir) &&
                       Directory.GetFiles(dir, "*.json").Any(f => ModuleJson.IsMatch(Path.GetFileName(f)));
            }
            catch { return false; }
        }

        public static LoadedScan Load(string dir)
        {
            var scan = new LoadedScan { Folder = dir };
            var js = Json.Serializer();

            foreach (string file in Directory.GetFiles(dir, "*.json").OrderBy(f => f, StringComparer.OrdinalIgnoreCase))
            {
                if (!ModuleJson.IsMatch(Path.GetFileName(file))) continue;
                try
                {
                    var r = ParseModule(js, File.ReadAllText(file));
                    if (r == null) continue;
                    r.JsonPath = file;
                    string html = Path.ChangeExtension(file, ".html");
                    if (!File.Exists(html))
                    {
                        // JSON is NN_Title_With_Underscores.json, HTML is NN_TitleCamel.html
                        var def = ModuleCatalog.ByNumber(r.Module);
                        if (def != null) html = Path.Combine(dir, Path.ChangeExtension(def.File, ".html"));
                    }
                    r.HtmlPath = File.Exists(html) ? html : "";
                    scan.Modules.Add(r);
                }
                catch { /* a damaged module file shouldn't sink the rest of the scan */ }
            }

            var first = scan.Modules.FirstOrDefault();
            if (first != null)
            {
                scan.Hostname = first.Hostname;
                scan.Version = first.Version;
            }

            // scan.json (written by this app) carries timing; otherwise fall back
            // to the folder's timestamp name, then the earliest module time.
            var meta = ReadScanMeta(js, Path.Combine(dir, "scan.json"));
            if (meta != null)
            {
                scan.Started = meta.Item1;
                scan.Duration = meta.Item2;
                if (string.IsNullOrEmpty(scan.Hostname)) scan.Hostname = meta.Item3;
            }
            else
            {
                scan.Started = StampFromFolder(dir) ?? EarliestModuleTime(scan) ?? Directory.GetCreationTime(dir);
            }
            if (string.IsNullOrEmpty(scan.Hostname))
                scan.Hostname = Path.GetFileName(Path.GetDirectoryName(dir.TrimEnd('\\')) ?? "") ?? "";
            return scan;
        }

        static ModuleResult ParseModule(JavaScriptSerializer js, string text)
        {
            var root = js.DeserializeObject(text) as Dictionary<string, object>;
            if (root == null) return null;
            var r = new ModuleResult
            {
                Module = Json.Str(root, "module"),
                Title = Json.Str(root, "title"),
                Hostname = Json.Str(root, "hostname"),
                ScanTime = Json.Str(root, "scanTime"),
                Version = Json.Str(root, "version"),
                Admin = Json.Bool(root, "admin"),
            };
            if (string.IsNullOrEmpty(r.Module)) return null;

            foreach (var item in Json.List(root, "findings"))
            {
                var f = item as Dictionary<string, object>;
                if (f == null) continue;
                r.Findings.Add(new Finding
                {
                    Severity = Severity.Normalize(Json.Str(f, "severity")),
                    Title = Json.Str(f, "title"),
                    Detail = Json.Str(f, "detail"),
                    WhyItMatters = Json.Str(f, "whyItMatters"),
                    WhyMightBeNormal = Json.Str(f, "whyMightBeNormal"),
                    CreatedDate = Json.Str(f, "createdDate"),
                    Sid = Json.Str(f, "sid"),
                    ModuleNumber = r.Module,
                    ModuleTitle = r.Title,
                });
            }

            // Count from the findings themselves; the summary block is a cache of the same thing.
            r.Red = r.Findings.Count(x => x.Severity == Severity.Red);
            r.Yellow = r.Findings.Count(x => x.Severity == Severity.Yellow);
            r.Green = r.Findings.Count(x => x.Severity == Severity.Green);
            r.Info = r.Findings.Count(x => x.Severity == Severity.Info);
            return r;
        }

        static Tuple<DateTime, TimeSpan?, string> ReadScanMeta(JavaScriptSerializer js, string path)
        {
            try
            {
                if (!File.Exists(path)) return null;
                var root = js.DeserializeObject(File.ReadAllText(path)) as Dictionary<string, object>;
                if (root == null) return null;
                DateTime started;
                if (!DateTime.TryParse(Json.Str(root, "started"), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out started))
                    return null;
                TimeSpan? dur = null;
                double secs;
                if (double.TryParse(Json.Str(root, "durationSeconds"), NumberStyles.Float, CultureInfo.InvariantCulture, out secs))
                    dur = TimeSpan.FromSeconds(secs);
                return Tuple.Create(started, dur, Json.Str(root, "hostname"));
            }
            catch { return null; }
        }

        static DateTime? StampFromFolder(string dir)
        {
            var m = FolderStamp.Match(Path.GetFileName(dir.TrimEnd('\\')));
            if (!m.Success) return null;
            DateTime dt;
            string s = m.Groups[1].Value + " " + m.Groups[2].Value + ":" + m.Groups[3].Value + ":" + m.Groups[4].Value;
            if (DateTime.TryParseExact(s, "yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture, DateTimeStyles.None, out dt))
                return dt;
            return null;
        }

        static DateTime? EarliestModuleTime(LoadedScan scan)
        {
            DateTime best = DateTime.MaxValue;
            foreach (var m in scan.Modules)
            {
                DateTime dt;
                if (DateTime.TryParse(m.ScanTime, CultureInfo.InvariantCulture, DateTimeStyles.None, out dt) && dt < best)
                    best = dt;
            }
            return best == DateTime.MaxValue ? (DateTime?)null : best;
        }
    }

    // Thin helpers over JavaScriptSerializer's Dictionary/object[] output.
    public static class Json
    {
        public static JavaScriptSerializer Serializer()
        {
            return new JavaScriptSerializer { MaxJsonLength = 64 * 1024 * 1024, RecursionLimit = 64 };
        }

        public static string Str(Dictionary<string, object> d, string key)
        {
            object v;
            if (d == null || !d.TryGetValue(key, out v) || v == null) return "";
            if (v is string) return (string)v;
            if (v is IFormattable) return ((IFormattable)v).ToString(null, CultureInfo.InvariantCulture);
            return v.ToString();
        }

        public static bool Bool(Dictionary<string, object> d, string key)
        {
            object v;
            return d != null && d.TryGetValue(key, out v) && v is bool && (bool)v;
        }

        public static IEnumerable<object> List(Dictionary<string, object> d, string key)
        {
            object v;
            if (d == null || !d.TryGetValue(key, out v) || v == null) return Enumerable.Empty<object>();
            var arr = v as object[];
            if (arr != null) return arr;
            var list = v as System.Collections.ArrayList;
            if (list != null) return list.Cast<object>();
            // ConvertTo-Json on PS 5.1 can unwrap a one-element array into a bare object
            return new[] { v };
        }
    }
}
