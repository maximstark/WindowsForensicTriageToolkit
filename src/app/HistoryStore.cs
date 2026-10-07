// =============================================================================
// HistoryStore.cs -- the scan history is the filesystem
// =============================================================================
// v2.0 keeps no separate history database: a scan is a folder under
// <output root>\<HOST>\<yyyy-MM-dd_HH-mm-ss>, so history is whatever is on
// disk there. Run from a USB stick, the toolkit leaves its history with the
// evidence instead of in the examined machine's profile. The v1.5 history
// file (%APPDATA%\TriageToolkit\scan_history.json) is still read so older
// scans stay reachable; it is never written.
// =============================================================================

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace TriageToolkit
{
    public static class HistoryStore
    {
        public static List<HistoryItemVM> Load(string outputRoot, IEnumerable<string> extraFolders)
        {
            var folders = new List<string>();
            folders.AddRange(Discover(outputRoot).Select(t => t.Item1));
            folders.AddRange(LegacyFolders());
            folders.AddRange(extraFolders ?? Enumerable.Empty<string>());

            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var items = new List<HistoryItemVM>();
            foreach (string f in folders)
            {
                string key;
                try { key = Path.GetFullPath(f).TrimEnd('\\'); } catch { continue; }
                if (!seen.Add(key) || !ScanLoader.LooksLikeScanFolder(key)) continue;
                try
                {
                    var s = ScanLoader.Load(key);
                    items.Add(new HistoryItemVM
                    {
                        Folder = key,
                        Hostname = s.Hostname,
                        Started = s.Started,
                        Red = s.Red, Yellow = s.Yellow, Green = s.Green, Info = s.Info,
                        ModuleCount = s.Modules.Count,
                    });
                }
                catch { }
            }
            return items.OrderByDescending(i => i.Started).ToList();
        }

        // Scan folders at most two levels below dir (root\HOST\stamp), or dir itself.
        public static List<Tuple<string, DateTime>> Discover(string dir)
        {
            var found = new List<Tuple<string, DateTime>>();
            try
            {
                if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) return found;
                var candidates = new List<string> { dir };
                foreach (string host in Directory.GetDirectories(dir))
                {
                    candidates.Add(host);
                    try { candidates.AddRange(Directory.GetDirectories(host)); } catch { }
                }
                foreach (string c in candidates)
                    if (ScanLoader.LooksLikeScanFolder(c))
                        found.Add(Tuple.Create(c, Directory.GetCreationTime(c)));
            }
            catch { }
            return found;
        }

        static IEnumerable<string> LegacyFolders()
        {
            var list = new List<string>();
            try
            {
                string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "TriageToolkit", "scan_history.json");
                if (!File.Exists(path)) return list;
                var arr = Json.Serializer().DeserializeObject(File.ReadAllText(path)) as object[];
                if (arr == null) return list;
                foreach (var o in arr)
                {
                    var d = o as Dictionary<string, object>;
                    string p = Json.Str(d, "reportPath");
                    if (!string.IsNullOrEmpty(p) && Directory.Exists(p)) list.Add(p);
                }
            }
            catch { }
            return list;
        }
    }
}
