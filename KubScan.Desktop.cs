using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace KubScan;

public static partial class App
{
    // The desktop process owns one session. Network workers and data are shared
    // with the existing application, without routing GUI actions through console input.
    public static class Desktop
    {
        public enum Mode { Ip, Mdns, Arp }

        public sealed record Row(object Key, string[] Cells, int Presence = 0);
        public sealed record Adapter(string Key, string Label)
        {
            public override string ToString() => Label;
        }
        public sealed record Status(string Text, bool Running, int Done = 0, int Total = 0);
        public sealed record Palette(string Name, int Background, int Panel, int Text, int Accent);
        public sealed record ToolStatus(string Text, bool Running, int Done = 0, int Total = 0);
        private static string scanError;
        private static Row[] cachedIpRows;
        private static (Task Scan, Task Oui, string Filter, int Column, bool Descending, bool English, bool Continuous) cachedIpKey;

        public static Task InitializeAsync() => Task.Run(() =>
        {
            ports = Launcher.DefaultPorts;
            InitializeSettings();
            PrepareBundledOui();
        });

        public static string DefaultTarget() => DefaultSubnet();
        public static string[] Prefixes(string address)
        {
            Parse(address + "/32");
            return Enumerable.Range(0, 17).Select(index => FormatCidrOption(address, index)).ToArray();
        }
        public static bool IsContinuous => continuousMode;
        public static bool HasContinuousResults => continuousList;
        public static bool IpScanCompleted => scan?.Status == TaskStatus.RanToCompletion && cancel?.IsCancellationRequested == false;
        public static string LastTarget() => hasScan ? scannedSubnet :
            throw new InvalidOperationException(Text("Noch kein Scan zum Wiederholen vorhanden.", "No scan to repeat."));

        public static string NormalizeTarget(string target) => ScanTargetLabel(target, Parse(target));
        public static string Text(string de, string en) => ServiceText(de, en);

        public static void StartIp(string target, bool continuous)
        {
            if (scan != null && !scan.IsCompleted)
                throw new InvalidOperationException(Text("Ein Scan läuft bereits.", "A scan is already running."));
            scanError = null;
            target = target.Trim();
            if (continuous)
            {
                if (target.Length > 0 && !target.Contains("/") && !target.Contains("-")) target += "/32";
                var addresses = Parse(target);
                if (!hasScan || ScanTargetLabel(target, addresses) != scannedSubnet) hosts.Clear();
                cancel?.Dispose();
                StartContinuousScan(target, addresses);
            }
            else
            {
                var addresses = Parse(target);
                cancel?.Dispose();
                StartIpScan(target, addresses);
            }
        }

        public static void EnterMode(Mode mode)
        {
            if (mode == Mode.Mdns) StartMdns();
            else if (mode == Mode.Arp) StartArp(false);
        }

        public static async Task StopAsync(Mode mode)
        {
            if (mode == Mode.Ip)
            {
                cancel?.Cancel();
                try { if (scan != null) await scan; }
                catch (OperationCanceledException) { }
                catch (Exception error) { scanError = error.Message; }
            }
            else if (mode == Mode.Mdns)
            {
                mdnsCancel?.Cancel();
                if (mdnsTask != null) await mdnsTask;
            }
            else
            {
                arpCancel?.Cancel();
                if (arpTask != null) await arpTask;
            }
        }

        public static void RestartArp() => StartArp(true);
        public static async Task<Adapter[]> AdaptersAsync() => await Task.Run(() =>
            DiscoverArpAdapters().Select(a => new Adapter(a.Key, a.Label)).ToArray());
        public static string AdapterKey => arpAdapterKey;
        public static async Task SelectAdapterAsync(Adapter adapter)
        {
            if (arpAdapterKey == adapter.Key) return;
            await StopAsync(Mode.Arp);
            arpAdapterKey = adapter.Key;
            arpAdapterLabel = adapter.Label;
            StartArp(true);
        }

        public static Row[] Results(Mode mode, string filter, int column, bool descending = false)
        {
            searchText = filter ?? "";
            if (mode == Mode.Ip)
            {
                sortColumn = Math.Clamp(column, 0, 3);
                var key = (scan, ouiUpdate, searchText, sortColumn, descending, English, continuousList);
                bool stable = (scan == null || scan.IsCompleted) && (ouiUpdate == null || ouiUpdate.IsCompleted);
                if (stable && cachedIpRows != null && cachedIpKey == key) return cachedIpRows;
                cachedIpRows = null;
                var sorted = SortHosts(false);
                if (descending) Array.Reverse(sorted);
                var result = sorted.Select(h => new Row(h.IP, new[]
                {
                    h.IP, DisplayHostName(h), DisplayStatus(h.MAC), DisplayStatus(h.Vendor)
                }, continuousList ? h.PresenceChange : 0)).ToArray();
                // Completed scans are immutable for these columns until another
                // scan/OUI update starts. Avoid sorting and allocating on every UI tick.
                if (stable) { cachedIpKey = key; cachedIpRows = result; }
                return result;
            }
            if (mode == Mode.Mdns)
            {
                mdnsSort = Math.Clamp(column, 0, 4);
                var sorted = SortedMdns();
                if (descending) Array.Reverse(sorted);
                return sorted.Select(e => new Row(e.Identity, MdnsCells(e))).ToArray();
            }
            var requests = FilteredArp();
            var ordered = column switch
            {
                1 => requests.OrderBy(a => a.Adapter, StringComparer.OrdinalIgnoreCase),
                2 => requests.OrderBy(a => ParseIPv4(a.SenderIP)),
                3 => requests.OrderBy(a => a.SenderMAC, StringComparer.OrdinalIgnoreCase),
                4 => requests.OrderBy(a => ParseIPv4(a.TargetIP)),
                _ => requests.OrderBy(a => a.Time, StringComparer.Ordinal)
            };
            return (descending ? ordered.Reverse() : ordered).Select(a => new Row(a, new[]
            {
                a.Time, ExportTextValue(a.Adapter), a.SenderIP, a.SenderMAC, a.TargetIP
            })).ToArray();
        }

        private static string[] MdnsCells(MdnsEntry entry) =>
            new[] { entry.Name, entry.Type, entry.Host, entry.Address, entry.Port == 0 ? "?" : entry.Port.ToString() };

        public static string DetailHeading(Mode mode, Row row)
        {
            if (mode == Mode.Ip)
            {
                if (hosts.TryGetValue(ParseIPv4((string)row.Key), out var host) &&
                    host.NameSource != "Wird ermittelt ..." && host.NameSource != "Keine Antwort" &&
                    host.NameSource != "Abgebrochen" && UsableHostName(host.DNS)) return host.DNS;
                return row.Cells[0];
            }
            if (mode == Mode.Mdns)
                return !string.IsNullOrWhiteSpace(row.Cells[2]) ? row.Cells[2] :
                    !string.IsNullOrWhiteSpace(row.Cells[3]) ? row.Cells[3] : Text("Details", "Details");
            return row.Cells[2];
        }

        public enum DetailLink { None, Web, Share, Ssh, Telnet, Ftp, Rdp }

        public sealed record DetailField(string Name, string Value, DetailLink Link = DetailLink.None,
            string Target = null, int Port = 0);

        public static DetailField[] Details(Mode mode, Row row)
        {
            if (mode == Mode.Ip && hosts.TryGetValue(ParseIPv4((string)row.Key), out var host))
            {
                StartHostServices(host);
                var fields = GroupDetails(HostDetailLines(host, 4096)).Select(field =>
                {
                    if (field.Name == Text("Webserver", "Web server") && host.WebLinks is { Length: > 0 } web)
                        return field with { Link = DetailLink.Web, Target = string.Join("\n", web) };
                    if (field.Name == Text("SMB-Freigaben", "SMB shares") && host.SmbPaths is { Length: > 0 } shares)
                        return field with { Link = DetailLink.Share, Target = string.Join("\n", shares) };
                    return field;
                }).ToList();
                foreach (int port in OpenPortNumbers(host).Distinct())
                {
                    var link = port switch
                    {
                        22 => DetailLink.Ssh, 23 => DetailLink.Telnet, 21 => DetailLink.Ftp, _ => DetailLink.None
                    };
                    if (link != DetailLink.None) fields.Add(ConnectionField(link, host.IP, port));
                }
                return fields.ToArray();
            }
            if (mode == Mode.Mdns)
            {
                MdnsEntry entry;
                lock (mdnsLock) mdnsEntries.TryGetValue((string)row.Key, out entry);
                if (entry == null) return Array.Empty<DetailField>();
                ResolveMdnsMac(entry);
                var fields = GroupDetails(MdnsDetailLines(entry, 4096));
                var address = entry.Address.Split(',').Select(value => value.Trim())
                    .FirstOrDefault(value => System.Net.IPAddress.TryParse(value, out _));
                if (address == null || entry.Port is < 1 or > 65535) return fields;

                var service = entry.Type.Split('.')[0].ToLowerInvariant();
                var link = service switch
                {
                    "_ssh" => DetailLink.Ssh, "_telnet" => DetailLink.Telnet, "_ftp" => DetailLink.Ftp, _ => DetailLink.None
                };
                if (link != DetailLink.None) return fields.Append(ConnectionField(link, address, entry.Port)).ToArray();
                if (service is "_http" or "_https")
                {
                    string url = new UriBuilder(service.Substring(1), address, entry.Port).Uri.AbsoluteUri;
                    return fields.Append(new DetailField(Text("Webserver", "Web server"), url, DetailLink.Web, url)).ToArray();
                }
                return fields;
            }
            return Headers(mode).Zip(row.Cells, (heading, value) => new DetailField(heading, value)).ToArray();
        }

        public static IEnumerable<(string Label, DetailLink Link, string Target, int Port)> ContextConnections(Row row)
        {
            if (row.Key is not string address || !hosts.TryGetValue(ParseIPv4(address), out var host))
                yield break;

            var ports = OpenPortNumbers(host);
            if (ports.Contains(3389)) yield return (Text("RDP verbinden", "Connect via RDP"), DetailLink.Rdp, address, 3389);
            if (ports.Contains(22)) yield return (Text("SSH verbinden", "Connect via SSH"), DetailLink.Ssh, address, 22);

            var detected = (host.WebLinks ?? Array.Empty<string>()).Select(url => new Uri(url)).ToArray();
            foreach (var (scheme, port) in new[] { ("http", 80), ("https", 443) })
            {
                var url = detected.Where(uri => uri.Scheme == scheme && ports.Contains(uri.Port))
                    .OrderByDescending(uri => uri.Port == port).FirstOrDefault();
                if (url == null && ports.Contains(port) && !detected.Any(uri => uri.Port == port))
                    url = new UriBuilder(scheme, address, port).Uri;
                if (url != null)
                {
                    var protocol = scheme.ToUpperInvariant();
                    yield return (Text(protocol + " öffnen", "Open " + protocol), DetailLink.Web, url.AbsoluteUri, url.Port);
                }
            }
        }

        private static DetailField ConnectionField(DetailLink link, string address, int port)
        {
            string name = link switch { DetailLink.Ssh => "SSH", DetailLink.Ftp => "FTP", _ => "Telnet" };
            return new DetailField(name, new UriBuilder(name.ToLowerInvariant(), address, port).Uri.AbsoluteUri,
                link, address, port);
        }

        private static DetailField[] GroupDetails(IEnumerable<DetailLine> lines)
        {
            var fields = new List<DetailField>();
            string name = null;
            var values = new List<string>();
            foreach (var line in lines)
            {
                if (line.IsLabel)
                {
                    if (name != null) fields.Add(new DetailField(name, string.Join("\n", values)));
                    name = line.Text.TrimEnd(':');
                    values.Clear();
                }
                else if (!string.IsNullOrWhiteSpace(line.Text)) values.Add(line.Text.TrimEnd());
            }
            if (name != null) fields.Add(new DetailField(name, string.Join("\n", values)));
            return fields.ToArray();
        }

        public static string[] Headers(Mode mode) => mode switch
        {
            Mode.Ip => new[] { "IP", "DNS", "MAC", Text("Hersteller", "Vendor") },
            Mode.Mdns => new[] { "Name", Text("Dienst", "Service"), "Host", "IP", "Port" },
            _ => English ? new[] { "Time", "Adapter", "Sender IP", "Sender MAC", "Requested IP" }
                         : new[] { "Zeit", "Adapter", "Absender-IP", "Absender-MAC", "Angefragt IP" }
        };

        public static bool HasStartedRun(Mode mode) => mode switch
        {
            Mode.Ip => scan != null,
            Mode.Mdns => mdnsTask != null,
            _ => arpTask != null
        };

        public static Status Progress(Mode mode, int visible)
        {
            if (mode == Mode.Mdns)
                return new Status(TranslateMessage(mdnsStatus) + " · " + Text("Dienste", "Services") + " " + visible, mdnsTask != null && !mdnsTask.IsCompleted);
            if (mode == Mode.Arp)
            {
                long received = Interlocked.Read(ref arpReceived);
                return new Status(arpStatus + " · " + received + " ARP · " + Text("Aufbewahrt", "Retained") +
                    " " + Math.Min(received, ArpCapacity) + "/" + ArpCapacity, arpTask != null && !arpTask.IsCompleted);
            }

            bool running = scan != null && !scan.IsCompleted;
            string state = scanError ?? (scan?.IsFaulted == true ? scan.Exception.GetBaseException().Message :
                running ? (continuousMode ? Text("Continuous", "Continuous") : TranslateMessage("Scan laeuft")) :
                !hasScan ? TranslateMessage("Subnetz eingeben, Enter startet.") :
                cancel?.IsCancellationRequested == true ? Text("Scan abgebrochen", "Scan cancelled") :
                Text("Scan abgeschlossen", "Scan complete"));
            int found = hosts.Count;
            string deviceCount = visible == found ? found.ToString() : $"{visible}/{found}";
            return new Status(state + (hasScan ? " · " + scannedSubnet + " · " + deviceCount +
                " " + Text("Geräte", "devices") : ""), running, Volatile.Read(ref done), total);
        }

        public static string ExportName(bool csv, Mode mode = Mode.Ip) =>
            mode == Mode.Mdns ? "mDNS_" + SuggestedExportName(csv).Substring("IPScan_".Length) : SuggestedExportName(csv);
        public static void ExportToPath(string path, Mode mode = Mode.Ip)
        {
            var extension = System.IO.Path.GetExtension(path);
            bool csv = extension.Equals(".csv", StringComparison.OrdinalIgnoreCase);
            if (!csv && !extension.Equals(".txt", StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException(Text("Dateiendung muss .csv oder .txt sein.", "File extension must be .csv or .txt."));
            ExportFileName(System.IO.Path.GetFileName(path), csv);
            if (mode != Mode.Mdns)
            {
                WriteExport(path, csv, 120, System.IO.FileMode.Create);
                return;
            }

            string[][] services;
            lock (mdnsLock)
                services = mdnsEntries.Values.OrderBy(e => e.Name, StringComparer.OrdinalIgnoreCase)
                    .Select(MdnsCells).ToArray();
            using var writer = new System.IO.StreamWriter(path, false, new System.Text.UTF8Encoding(true));
            foreach (var cells in services.Prepend(Headers(Mode.Mdns)))
                writer.WriteLine(csv ? string.Join(";", cells.Select(CsvValue)) :
                    string.Join("\t", cells.Select(ExportTextValue)));
        }
        public static Palette[] Palettes() => themes.Select(t => new Palette(t.Name, t.Base, t.Panel, t.Text, t.Accent)).ToArray();

        private static Host GetHost(Row row)
        {
            if (row != null && row.Key is string address && hosts.TryGetValue(ParseIPv4(address), out var host))
                return host;
            throw new InvalidOperationException(Text("Bitte zuerst einen Host auswählen.", "Select a host first."));
        }

        public sealed class HostTool : IAsyncDisposable
        {
            private PortScanSession port;
            private PingSession ping;
            private OsSession os;
            private bool stopped;
            private bool paused;

            public HostTool(Row row, string operation, string input = "")
            {
                var host = GetHost(row);
                switch (operation)
                {
                    case "ping":
                        ping = new PingSession { Address = host.IP, Name = host.DNS };
                        RunContinuousPing(ping);
                        break;
                    case "os":
                        os = new OsSession { Host = host, Cancel = new CancellationTokenSource() };
                        os.Work = Task.Run(() => DetectOperatingSystem(os, OpenPortNumbers(host)));
                        break;
                    default:
                        var numbers = ParsePortSelection(input);
                        port = new PortScanSession { Host = host, Udp = operation == "udp" };
                        RunPortScan(port, numbers);
                        break;
                }
            }

            public async Task TogglePingAsync()
            {
                if (ping == null || stopped) return;
                if (!paused)
                {
                    paused = true;
                    ping.Cancel.Cancel();
                    await ping.Worker;
                    return;
                }
                if (!ping.Worker.IsCompleted) return;
                ping.Cancel.Dispose();
                ping.Cancel = new CancellationTokenSource();
                paused = false;
                RunContinuousPing(ping);
            }

            public bool Paused => paused;
            public void Cancel() { port?.Cancel.Cancel(); ping?.Cancel.Cancel(); os?.Cancel.Cancel(); }

            public ToolStatus Snapshot()
            {
                if (port != null)
                {
                    var lines = port.Udp
                        ? port.UdpResults.ToArray().OrderBy(p => p.Key).Select(p => p.Key + " / UDP   " + p.Value)
                        : port.Open.Keys.OrderBy(p => p).Select(p => p + " / TCP   " + PortService(p));
                    return new ToolStatus(string.Join("\n", new[] { port.Error }.Concat(lines).Where(s => s.Length > 0)),
                        port.Running, Volatile.Read(ref port.Done), port.Total);
                }
                if (ping != null)
                {
                    lock (ping.Sync)
                    {
                        string stats = Text("Gesendet / empfangen", "Sent / received") + "  " + ping.Sent + " / " + ping.Received;
                        if (ping.Received > 0)
                            stats += "\nMin / Ø / Max  " + FormatPing(ping.Minimum) + " / " +
                                FormatPing(ping.Sum / ping.Received) + " / " + FormatPing(ping.Maximum);
                        return new ToolStatus(stats + "\n\n" + string.Join("\n", ping.History.Reverse().Select(TranslatePingHistory)), ping.Running);
                    }
                }
                var guess = os.Result;
                return new ToolStatus(guess == null ? T("Wird ermittelt ...") :
                    T(guess.Family) + "\n" + T(guess.Confidence >= 2 ? "Sicherheit: starker Hinweis" :
                    guess.Confidence == 1 ? "Sicherheit: schwacher Hinweis" : "Sicherheit: unbestimmt") +
                    "\n\n" + string.Join("\n", guess.Evidence.Split('\n').Select(T)) +
                    "\n\n" + T("Keine sichere Identifikation."), !os.Work.IsCompleted);
            }

            public async ValueTask DisposeAsync()
            {
                if (stopped) return;
                stopped = true;
                Cancel();
                try { await (port?.Worker ?? ping?.Worker ?? os.Work); }
                finally { port?.Cancel.Dispose(); ping?.Cancel.Dispose(); os?.Cancel.Dispose(); }
            }
        }

        public static void StartOuiUpdate(CancellationToken token) => BeginOuiUpdate(token);
        public static Task FinishOuiUpdateAsync() => ouiUpdate ?? Task.CompletedTask;
        public static ToolStatus OuiStatus() => new ToolStatus(
            TranslateMessage(exportMessage) + "\n" + TranslateMessage(ouiPhase),
            ouiUpdate != null && !ouiUpdate.IsCompleted, ouiProgress, 100);

        public static async Task ShutdownAsync()
        {
            await Task.WhenAll(StopAsync(Mode.Ip), StopAsync(Mode.Mdns), StopAsync(Mode.Arp));
            cancel?.Dispose();
            mdnsCancel?.Dispose();
            arpCancel?.Dispose();
        }
    }
}
