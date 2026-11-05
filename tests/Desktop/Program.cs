using Backend = KubScan.App.Desktop;

static void Require(bool condition, string message)
{
    if (!condition) throw new InvalidOperationException(message);
}

await Backend.InitializeAsync();
try
{
    var flags = System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static;
    var sourceField = typeof(KubScan.App).GetField("ouiSource", flags);
    var source = (Lazy<Dictionary<string, string>>)sourceField.GetValue(null);
    Require(!source.IsValueCreated, "Desktop startup must not parse the OUI database.");
    var vendor = typeof(KubScan.App).GetMethod("Vendor", flags);
    Require((string)vendor.Invoke(null, ["02:11:22:33:44:55"]) == "Lokal/privat oder Multicast",
        "Private MAC fallback changed.");
    Require(!source.IsValueCreated, "Private MAC addresses must not load the OUI database.");
    var lookups = await Task.WhenAll(Enumerable.Range(0, 16).Select(_ => Task.Run(() =>
        (string)vendor.Invoke(null, ["00:11:22:33:44:55"]))));
    Require(source.IsValueCreated && source.Value.Count > 1000 && lookups.Distinct().Count() == 1,
        "Concurrent first lookups must share a complete OUI database.");

    var initial = Backend.DefaultTarget();
    if (initial.Length > 0)
        Require(initial.EndsWith(".0/24") && Backend.NormalizeTarget(initial) == initial, "Invalid adapter default.");
    Require(Backend.NormalizeTarget("10.1.2.123/24") == "10.1.2.0/24", "CIDR was not normalized.");
    Require(Backend.NormalizeTarget("10.1.2.3-5") == "10.1.2.3-10.1.2.5", "Short range was not expanded.");
    var choices = Backend.Prefixes("10.1.2.123");
    Require(choices.Length == 17 && choices[0].StartsWith("/32 ") && choices[8].Contains("10.1.2.1 - 10.1.2.254")
        && choices[16].StartsWith("/16 "), "Wrong prefix options.");

    var mode = Backend.Mode.Ip;
    Backend.StartIp("127.0.0.1/32", false);
    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
    while (Backend.Progress(mode, 0).Running) await Task.Delay(25, timeout.Token);
    var rows = Backend.Results(mode, "", 0);
    Require(rows.Length == 1 && rows[0].Cells.Length == 4 && rows[0].Cells[0] == "127.0.0.1", "No loopback result.");
    Require(ReferenceEquals(rows, Backend.Results(mode, "", 0)), "Idle refresh should reuse completed results.");
    Require(Backend.Results(mode, "does-not-match", 3).Length == 0, "Filter was not applied.");
    try
    {
        Backend.StartIp("127.0.0.1/15", false);
        throw new InvalidOperationException("Invalid range started a scan.");
    }
    catch (ArgumentException) { }
    Require(Backend.Results(mode, "", 0).Length == 1, "Invalid input discarded results.");

    var hostField = typeof(KubScan.App).GetField("hosts",
        System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
    var hosts = (System.Collections.Concurrent.ConcurrentDictionary<uint, KubScan.Host>)hostField.GetValue(null);
    var host = hosts.Values.Single();
    host.Ports = "22, 80, 443, 3389";
    var connections = Backend.ContextConnections(rows[0]).ToArray();
    Require(connections.Select(connection => connection.Port).SequenceEqual(new[] { 3389, 22, 80, 443 }),
        "Connection commands must follow RDP, SSH, HTTP, HTTPS order.");
    host.Ports = "8443";
    host.WebLinks = ["https://127.0.0.1:8443/"];
    Require(Backend.ContextConnections(rows[0]).Single().Target == host.WebLinks[0],
        "Confirmed web services must use the detected port.");
    host.Ports = "";
    Require(!Backend.ContextConnections(rows[0]).Any(), "Closed ports must not offer connections.");

    Backend.StartIp("127.0.0.2/32", true);
    Require(Backend.IsContinuous && Backend.LastTarget() == "127.0.0.2/32", "Continuous scan must use the newly entered target.");
    await Backend.StopAsync(mode).WaitAsync(timeout.Token);
    Require(!Backend.Progress(mode, 0).Running, "Continuous scan did not stop.");
    Require(!ReferenceEquals(rows, Backend.Results(mode, "", 0)), "A new scan must invalidate cached results.");
    Console.WriteLine("OK: Desktop defaults, CIDR options, loopback scan, filtering, validation and continuous cancellation.");
}
finally
{
    await Backend.ShutdownAsync();
}
