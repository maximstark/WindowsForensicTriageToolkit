// =============================================================================
// ReportWriter.cs -- files the app adds to a scan folder
// =============================================================================
//   scan.json         timing, options and per-module outcome of this run
//   00_Summary.html   one-page index across all module reports
//   manifest.json     SHA-256 + size of every file in the folder (written last),
//                     so a copied evidence folder can be checked for tampering
// Plus on-demand CSV export of findings.
// =============================================================================

using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;

namespace TriageToolkit
{
    public static class ReportWriter
    {
        static readonly UTF8Encoding Utf8NoBom = new UTF8Encoding(false);

        public static void WriteScanMeta(ScanResult r, ScanOptions o)
        {
            var modules = r.Runs.Select(run => (object)new Dictionary<string, object>
            {
                { "module", run.Def.Number },
                { "name", run.Def.Name },
                { "outcome", run.Outcome.ToString() },
                { "seconds", Math.Round(run.Elapsed.TotalSeconds, 1) },
                { "exitCode", run.ExitCode },
            }).ToList();

            var meta = new Dictionary<string, object>
            {
                { "tool", "Windows Forensic Triage Toolkit" },
                { "version", BuildInfo.Version },
                { "hostname", Environment.MachineName },
                { "user", Environment.UserDomainName + "\\" + Environment.UserName },
                { "started", r.Started.ToString("o", CultureInfo.InvariantCulture) },
                { "finished", r.Finished.ToString("o", CultureInfo.InvariantCulture) },
                { "durationSeconds", Math.Round((r.Finished - r.Started).TotalSeconds, 1) },
                { "cancelled", r.Cancelled },
                { "networkWatchMinutes", o.NetMinutes },
                { "modules", modules },
            };
            File.WriteAllText(Path.Combine(r.ReportDir, "scan.json"), PrettyJson(meta), Utf8NoBom);
        }

        public static void WriteManifest(string dir, string hostname)
        {
            var files = new List<object>();
            foreach (string f in Directory.GetFiles(dir).OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
            {
                string name = Path.GetFileName(f);
                if (name.Equals("manifest.json", StringComparison.OrdinalIgnoreCase)) continue;
                files.Add(new Dictionary<string, object>
                {
                    { "file", name },
                    { "bytes", new FileInfo(f).Length },
                    { "sha256", ScanEngine.Sha256File(f) },
                });
            }
            var manifest = new Dictionary<string, object>
            {
                { "generated", DateTime.Now.ToString("o", CultureInfo.InvariantCulture) },
                { "toolVersion", BuildInfo.Version },
                { "hostname", hostname },
                { "note", "SHA-256 of every report file at the moment the scan finished. Re-hash to verify a copied folder." },
                { "files", files },
            };
            File.WriteAllText(Path.Combine(dir, "manifest.json"), PrettyJson(manifest), Utf8NoBom);
        }

        // Returns (ok, total, mismatched-or-missing names) for a folder with a manifest.json.
        public static Tuple<bool, int, List<string>> VerifyManifest(string dir)
        {
            string path = Path.Combine(dir, "manifest.json");
            var bad = new List<string>();
            if (!File.Exists(path)) return null;
            var root = Json.Serializer().DeserializeObject(File.ReadAllText(path)) as Dictionary<string, object>;
            int total = 0;
            foreach (var item in Json.List(root, "files"))
            {
                var d = item as Dictionary<string, object>;
                if (d == null) continue;
                total++;
                string file = Path.Combine(dir, Json.Str(d, "file"));
                if (!File.Exists(file) || !string.Equals(ScanEngine.Sha256File(file), Json.Str(d, "sha256"), StringComparison.OrdinalIgnoreCase))
                    bad.Add(Json.Str(d, "file"));
            }
            return Tuple.Create(bad.Count == 0, total, bad);
        }

        public static void WriteCsv(IEnumerable<Finding> findings, string path)
        {
            var sb = new StringBuilder();
            sb.AppendLine("Severity,Module,Module Title,Title,Detail,Why It Matters,May Be Normal,Created,SID");
            foreach (var f in findings)
            {
                sb.AppendLine(string.Join(",", new[]
                {
                    Severity.Label(f.Severity), f.ModuleNumber, f.ModuleTitle, f.Title, f.Detail,
                    f.WhyItMatters, f.WhyMightBeNormal, f.CreatedDate, f.Sid
                }.Select(Csv)));
            }
            // BOM so Excel opens it as UTF-8
            File.WriteAllText(path, sb.ToString(), new UTF8Encoding(true));
        }

        static string Csv(string s)
        {
            s = s ?? "";
            // Neutralise spreadsheet formula injection: finding text can come from
            // attacker-controlled names (tasks, services, history lines).
            if (s.Length > 0 && "=+-@\t\r".IndexOf(s[0]) >= 0) s = "'" + s;
            if (s.IndexOfAny(new[] { ',', '"', '\n', '\r' }) >= 0) s = "\"" + s.Replace("\"", "\"\"") + "\"";
            return s;
        }

        // ---------------------------------------------------------------------
        // 00_Summary.html
        // ---------------------------------------------------------------------
        public static void WriteSummaryHtml(LoadedScan scan)
        {
            var sb = new StringBuilder();
            string host = H(scan.Hostname);
            sb.Append("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\">");
            sb.Append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
            sb.Append("<title>Triage summary -- ").Append(host).Append("</title><style>").Append(Css).Append("</style></head><body>");

            sb.Append("<div class=\"header\"><div class=\"module-num\">Scan summary</div><h1>").Append(host).Append("</h1><div class=\"meta\">");
            Meta(sb, "Scanned", scan.Started.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture));
            if (scan.Duration.HasValue) Meta(sb, "Duration", Format.Duration(scan.Duration.Value));
            Meta(sb, "Modules", scan.Modules.Count.ToString(CultureInfo.InvariantCulture));
            Meta(sb, "Toolkit", "v" + BuildInfo.Version);
            sb.Append("</div></div>");

            var v = Verdict.For(scan.Red, scan.Yellow);
            sb.Append("<div class=\"verdict verdict-").Append(v.Css).Append("\"><div class=\"verdict-title\">")
              .Append(H(v.Title)).Append("</div><div class=\"verdict-sub\">").Append(H(v.Subtitle)).Append("</div></div>");

            sb.Append("<div class=\"summary-bar\">");
            Pill(sb, "red", scan.Red, "Critical");
            Pill(sb, "yellow", scan.Yellow, "Warning");
            Pill(sb, "green", scan.Green, "Clean");
            Pill(sb, "info", scan.Info, "Info");
            sb.Append("</div>");

            sb.Append("<div class=\"section\"><div class=\"section-header\"><span class=\"section-title\">Modules</span></div><div class=\"section-body\"><table><thead><tr>")
              .Append("<th>#</th><th>Module</th><th>Critical</th><th>Warning</th><th>Clean</th><th>Info</th><th>Report</th></tr></thead><tbody>");
            foreach (var m in scan.Modules.OrderBy(x => x.Module))
            {
                sb.Append("<tr><td class=\"mono\">").Append(H(m.Module)).Append("</td><td>").Append(H(m.Title)).Append("</td>");
                Count(sb, m.Red, "red"); Count(sb, m.Yellow, "yellow"); Count(sb, m.Green, "green"); Count(sb, m.Info, "info");
                sb.Append("<td>");
                if (!string.IsNullOrEmpty(m.HtmlPath))
                    sb.Append("<a href=\"").Append(H(Uri.EscapeDataString(Path.GetFileName(m.HtmlPath)))).Append("\">Open</a>");
                sb.Append("</td></tr>");
            }
            sb.Append("</tbody></table></div></div>");

            var important = scan.AllFindings.Where(f => f.Severity == Severity.Red || f.Severity == Severity.Yellow)
                .OrderBy(f => Severity.Rank(f.Severity)).ThenBy(f => f.ModuleNumber).ToList();
            sb.Append("<div class=\"section\"><div class=\"section-header\"><span class=\"section-title\">Findings to review (")
              .Append(important.Count).Append(")</span></div><div class=\"section-body\">");
            if (important.Count == 0) sb.Append("<p class=\"no-findings\">[OK] No critical or warning findings.</p>");
            foreach (var f in important)
            {
                string c = f.Severity == Severity.Red ? "red" : "yellow";
                sb.Append("<div class=\"finding finding-").Append(c).Append("\"><div class=\"finding-title\"><span class=\"badge badge-").Append(c).Append("\">")
                  .Append(H(f.Severity)).Append("</span> ").Append(H(f.Title)).Append(" <span class=\"module-tag\">").Append(H(f.ModuleNumber + " " + f.ModuleTitle)).Append("</span></div>")
                  .Append("<div class=\"finding-detail\">").Append(H(f.Detail)).Append("</div>")
                  .Append("<div class=\"finding-why\">").Append(H(f.WhyItMatters)).Append("</div>");
                if (!string.IsNullOrEmpty(f.WhyMightBeNormal))
                    sb.Append("<div class=\"finding-normal\">[i] May be normal: ").Append(H(f.WhyMightBeNormal)).Append("</div>");
                sb.Append("</div>");
            }
            sb.Append("</div></div>");

            sb.Append("<div class=\"footer\">Windows Forensic Triage Toolkit v").Append(H(BuildInfo.Version))
              .Append(" -- Read-only forensic tool -- No system changes made</div></body></html>");
            File.WriteAllText(scan.SummaryHtml, sb.ToString(), Utf8NoBom);
        }

        static string H(string s) { return WebUtility.HtmlEncode(s ?? ""); }

        static void Meta(StringBuilder sb, string k, string v)
        {
            sb.Append("<div class=\"meta-item\">").Append(H(k)).Append(": <span>").Append(H(v)).Append("</span></div>");
        }

        static void Pill(StringBuilder sb, string cls, int n, string label)
        {
            if (n > 0) sb.Append("<span class=\"pill pill-").Append(cls).Append("\">").Append(n).Append(' ').Append(label).Append("</span>");
        }

        static void Count(StringBuilder sb, int n, string cls)
        {
            if (n > 0) sb.Append("<td><span class=\"badge badge-").Append(cls).Append("\">").Append(n).Append("</span></td>");
            else sb.Append("<td class=\"zero\">0</td>");
        }

        const string Css = @"
:root{--bg:#0f1117;--surface:#1a1d27;--border:#2a2d3a;--text:#e2e8f0;--muted:#64748b;--green:#22c55e;--green-bg:#052e16;--yellow:#eab308;--yellow-bg:#1c1a05;--red:#ef4444;--red-bg:#2d0a0a;--blue:#3b82f6;--blue-bg:#0a1628;--mono:'Cascadia Mono',Consolas,'Courier New',monospace}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:14px;line-height:1.6;padding:2rem;max-width:1200px;margin:0 auto}
a{color:var(--blue);text-decoration:none}a:hover{text-decoration:underline}
.header{border-bottom:1px solid var(--border);padding-bottom:1.5rem;margin-bottom:1.5rem}
.header h1{font-size:1.6rem;font-weight:700}
.module-num{color:var(--blue);font-size:.85rem;font-weight:600;letter-spacing:.1em;text-transform:uppercase;margin-bottom:.3rem}
.meta{display:flex;gap:2rem;margin-top:.8rem;flex-wrap:wrap}.meta-item{font-size:.8rem;color:var(--muted)}.meta-item span{color:var(--text);font-weight:500}
.verdict{border-radius:8px;padding:1rem 1.2rem;margin-bottom:1.2rem;border:1px solid;border-left-width:4px}
.verdict-title{font-size:1.15rem;font-weight:700}.verdict-sub{color:var(--muted);font-size:.85rem}
.verdict-red{background:var(--red-bg);border-color:var(--red)}.verdict-yellow{background:var(--yellow-bg);border-color:var(--yellow)}.verdict-green{background:var(--green-bg);border-color:var(--green)}
.summary-bar{display:flex;gap:1rem;margin-bottom:2rem;flex-wrap:wrap}
.pill{padding:.4rem 1rem;border-radius:999px;font-size:.82rem;font-weight:600}
.pill-red{background:var(--red-bg);color:var(--red);border:1px solid var(--red)}.pill-yellow{background:var(--yellow-bg);color:var(--yellow);border:1px solid var(--yellow)}
.pill-green{background:var(--green-bg);color:var(--green);border:1px solid var(--green)}.pill-info{background:var(--blue-bg);color:var(--blue);border:1px solid var(--blue)}
.section{background:var(--surface);border:1px solid var(--border);border-radius:8px;margin-bottom:1.5rem;overflow:hidden}
.section-header{padding:.9rem 1.2rem;background:rgba(255,255,255,.03);border-bottom:1px solid var(--border)}
.section-title{font-weight:600;font-size:.95rem}.section-body{padding:1.2rem}
table{width:100%;border-collapse:collapse;font-size:.85rem}
th{text-align:left;padding:.5rem .8rem;color:var(--muted);font-weight:600;font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;border-bottom:1px solid var(--border)}
td{padding:.5rem .8rem;border-bottom:1px solid rgba(255,255,255,.04)}td.zero{color:var(--muted)}
.mono{font-family:var(--mono)}
.badge{display:inline-block;padding:.15rem .5rem;border-radius:4px;font-size:.72rem;font-weight:700;text-transform:uppercase}
.badge-red{background:var(--red-bg);color:var(--red)}.badge-yellow{background:var(--yellow-bg);color:var(--yellow)}.badge-green{background:var(--green-bg);color:var(--green)}.badge-info{background:var(--blue-bg);color:var(--blue)}
.finding{border-radius:6px;padding:.8rem 1rem;margin-bottom:.8rem;border-left:3px solid}
.finding-red{background:var(--red-bg);border-color:var(--red)}.finding-yellow{background:var(--yellow-bg);border-color:var(--yellow)}
.finding-title{font-weight:600;margin-bottom:.3rem}.module-tag{color:var(--muted);font-weight:400;font-size:.78rem;margin-left:.4rem}
.finding-detail{font-size:.82rem;margin-bottom:.4rem;font-family:var(--mono);word-break:break-word}
.finding-why{font-size:.78rem;color:var(--muted)}.finding-normal{font-size:.75rem;color:var(--muted);font-style:italic;margin-top:.3rem}
.no-findings{color:var(--muted);font-style:italic}
.footer{margin-top:3rem;padding-top:1rem;border-top:1px solid var(--border);font-size:.75rem;color:var(--muted);text-align:center}";

        // ---------------------------------------------------------------------
        // Minimal indented JSON writer (JavaScriptSerializer only does compact)
        // ---------------------------------------------------------------------
        public static string PrettyJson(object o)
        {
            var sb = new StringBuilder();
            WriteJson(sb, o, 0);
            sb.Append('\n');
            return sb.ToString();
        }

        static void WriteJson(StringBuilder sb, object o, int depth)
        {
            string pad = new string(' ', (depth + 1) * 2), end = new string(' ', depth * 2);
            if (o == null) { sb.Append("null"); return; }
            if (o is string) { sb.Append(Quote((string)o)); return; }
            if (o is bool) { sb.Append((bool)o ? "true" : "false"); return; }
            if (o is IFormattable && !(o is DateTime)) { sb.Append(((IFormattable)o).ToString(null, CultureInfo.InvariantCulture)); return; }
            var dict = o as IDictionary<string, object>;
            if (dict != null)
            {
                if (dict.Count == 0) { sb.Append("{}"); return; }
                sb.Append("{\n");
                int i = 0;
                foreach (var kv in dict)
                {
                    sb.Append(pad).Append(Quote(kv.Key)).Append(": ");
                    WriteJson(sb, kv.Value, depth + 1);
                    sb.Append(++i < dict.Count ? ",\n" : "\n");
                }
                sb.Append(end).Append('}');
                return;
            }
            var list = o as IEnumerable;
            if (list != null)
            {
                var items = list.Cast<object>().ToList();
                if (items.Count == 0) { sb.Append("[]"); return; }
                sb.Append("[\n");
                for (int i = 0; i < items.Count; i++)
                {
                    sb.Append(pad);
                    WriteJson(sb, items[i], depth + 1);
                    sb.Append(i < items.Count - 1 ? ",\n" : "\n");
                }
                sb.Append(end).Append(']');
                return;
            }
            sb.Append(Quote(o.ToString()));
        }

        static string Quote(string s)
        {
            var sb = new StringBuilder("\"");
            foreach (char c in s)
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4"));
                        else sb.Append(c);
                        break;
                }
            }
            return sb.Append('"').ToString();
        }
    }

    public sealed class Verdict
    {
        public string Title, Subtitle, Css, Icon;

        public static Verdict For(int red, int yellow)
        {
            if (red > 0)
                return new Verdict
                {
                    Css = "red", Icon = "",
                    Title = Format.Plural(red, "critical finding needs", "critical findings need") + " attention",
                    Subtitle = (yellow > 0 ? Format.Plural(yellow, "warning", "warnings") + " to review as well. " : "") +
                               "Critical means the indicator is rarely benign; check each one against what the owner expects."
                };
            if (yellow > 0)
                return new Verdict
                {
                    Css = "yellow", Icon = "",
                    Title = Format.Plural(yellow, "warning", "warnings") + " to review",
                    Subtitle = "No critical indicators. Warnings are worth a look but are often explained by normal software."
                };
            return new Verdict
            {
                Css = "green", Icon = "",
                Title = "No critical or warning findings",
                Subtitle = "Nothing in this scan stood out. Absence of findings is not proof of absence of compromise."
            };
        }
    }
}
