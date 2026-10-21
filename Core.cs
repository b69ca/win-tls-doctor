using System.Diagnostics;
using System.Globalization;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace WinDiagnostics;

public sealed record Finding(string Id, string Severity, string Title, string Detail, string NextStep);
public sealed record Collection(JsonObject Evidence, JsonArray Issues);

public sealed class Options
{
    private readonly Dictionary<string, string> values = new(StringComparer.Ordinal);
    public bool Has(string key) => values.ContainsKey(key);
    public string Get(string key, string fallback = "") => values.GetValueOrDefault(key, fallback);
    public int Number(string key, int fallback, int minimum, int maximum)
    {
        if (!Has(key)) return fallback;
        if (!int.TryParse(Get(key), NumberStyles.None, CultureInfo.InvariantCulture, out var n) || n < minimum || n > maximum)
            throw new ArgumentException($"{key} must be an integer from {minimum} to {maximum}.");
        return n;
    }
    public static Options Parse(string[] args, string[] valueOptions, string[] flags)
    {
        var options = new Options();
        var names = valueOptions.Concat(["--input"]).ToHashSet(StringComparer.Ordinal);
        var switches = flags.Concat(["--json", "--help"]).ToHashSet(StringComparer.Ordinal);
        for (int i = 0; i < args.Length; i++)
        {
            var key = args[i];
            if (!names.Contains(key) && !switches.Contains(key)) throw new ArgumentException($"Unknown option: {key}");
            if (options.Has(key)) throw new ArgumentException($"Duplicate option: {key}");
            if (switches.Contains(key)) options.values[key] = "true";
            else
            {
                if (++i == args.Length || args[i].StartsWith("--", StringComparison.Ordinal)) throw new ArgumentException($"{key} requires a value.");
                options.values[key] = args[i];
            }
        }
        if (options.Has("--input") && valueOptions.Concat(flags).Any(options.Has))
            throw new ArgumentException("--input cannot be combined with live collection options.");
        return options;
    }
}

public static class J
{
    public static readonly JsonSerializerOptions Pretty = new() { WriteIndented = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    public static string Text(JsonNode? node, string key, string fallback = "") => node?[key]?.ToString() ?? fallback;
    public static double Number(JsonNode? node, string key, double fallback = 0) => double.TryParse(Text(node, key), NumberStyles.Float, CultureInfo.InvariantCulture, out var n) && double.IsFinite(n) ? n : fallback;
    public static bool Bool(JsonNode? node, string key) => bool.TryParse(Text(node, key), out var value) && value;
    public static IEnumerable<JsonObject> Rows(JsonNode? node, string key) => node?[key] is JsonArray array ? array.OfType<JsonObject>() : [];
    public static IEnumerable<string> Strings(JsonNode? node, string key) => node?[key] is JsonArray array ? array.Where(n => n is not null).Select(n => n!.ToString()) : [];
    public static void Require(JsonObject node, params string[] fields)
    {
        foreach (var key in fields) if (!node.ContainsKey(key)) throw new ArgumentException($"Evidence is missing '{key}'.");
    }
    public static void RequireRows(JsonObject node, string key)
    {
        if (node[key] is not JsonArray a || a.Any(n => n is not JsonObject)) throw new ArgumentException($"Evidence '{key}' must be an array of objects.");
    }
    public static JsonArray Array(IEnumerable<string> values) => new(values.Select(x => (JsonNode?)JsonValue.Create(x)).ToArray());
    public static string Host(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 253 || value.Any(char.IsWhiteSpace) || Uri.CheckHostName(value) == UriHostNameType.Unknown)
            throw new ArgumentException("Specify a valid DNS hostname or IP address.");
        return value;
    }
    public static string Bytes(double n) => $"{n / 1073741824d:F2} GiB ({n:F0} bytes)";
}

public static class Core
{
    public const int SchemaVersion = 1;
    public static async Task<int> Run(string[] args)
    {
        bool json = args.Contains("--json");
        try
        {
            var options = Options.Parse(args, Tool.ValueOptions, Tool.Flags);
            if (options.Has("--help")) { Console.WriteLine(Tool.Help + CommonHelp); return 0; }
            Collection collection;
            string collectedAt = DateTimeOffset.UtcNow.ToString("O"), platform = RuntimeInformation.OSDescription;
            bool offline = options.Has("--input");
            using var cancellation = new CancellationTokenSource();
            ConsoleCancelEventHandler handler = (_, e) => { e.Cancel = true; cancellation.Cancel(); };
            Console.CancelKeyPress += handler;
            try
            {
                if (offline)
                {
                    var path = options.Get("--input");
                    if (new FileInfo(path).Length > 8 * 1024 * 1024) throw new ArgumentException("Snapshot exceeds the 8 MiB limit.");
                    var snapshot = JsonNode.Parse(await File.ReadAllTextAsync(path, cancellation.Token), documentOptions: new JsonDocumentOptions { MaxDepth = 32 }) as JsonObject ?? throw new ArgumentException("Snapshot must be a JSON object.");
                    collection = ReadSnapshot(snapshot);
                    collectedAt = J.Text(snapshot, "collectedAtUtc", "not recorded");
                    platform = J.Text(snapshot, "platform", "not recorded");
                }
                else
                {
                    Tool.ValidateOptions(options);
                    if (!OperatingSystem.IsWindows()) { Console.Error.WriteLine($"{Tool.Name}: live collection requires Windows. Use --input FILE for offline analysis."); return 4; }
                    collection = await Tool.Collect(options, cancellation.Token);
                }
            }
            finally { Console.CancelKeyPress -= handler; }
            Tool.ValidateEvidence(collection.Evidence);
            var findings = Tool.Analyze(collection.Evidence);
            if (collection.Issues.Count > 0) findings.Add(new("collection-partial", "warning", "Some evidence could not be collected", "Read the collection issues before drawing conclusions. An empty result may reflect missing permissions or unavailable components.", "Retry only the affected checks with appropriate permissions; compare the saved evidence."));
            if (findings.Count == 0) findings.Add(new("no-rule-matched", "info", "No diagnostic rule matched", "The collected evidence did not trigger the current rules; this does not prove the system is healthy.", "Review the evidence and compare it with the reported symptom."));
            var report = new JsonObject
            {
                ["schemaVersion"] = SchemaVersion, ["tool"] = Tool.Name, ["version"] = "1.0.0", ["collectedAtUtc"] = collectedAt,
                ["analyzedAtUtc"] = DateTimeOffset.UtcNow.ToString("O"), ["mode"] = offline ? "offline" : "live", ["platform"] = platform,
                ["status"] = collection.Issues.Count > 0 ? "partial" : "complete", ["evidence"] = collection.Evidence,
                ["issues"] = collection.Issues, ["findings"] = JsonSerializer.SerializeToNode(findings, J.Pretty)
            };
            if (json) Console.WriteLine(report.ToJsonString(J.Pretty));
            else
            {
                Console.WriteLine($"{Tool.Name} | {report["status"]} | collected {collectedAt}");
                foreach (var line in Tool.Describe(collection.Evidence)) Console.WriteLine(line);
                foreach (var f in findings) Console.WriteLine($"\n[{f.Severity.ToUpperInvariant()}] {f.Title}\n  {f.Detail}\n  Next: {f.NextStep}");
                foreach (var issue in collection.Issues) Console.WriteLine($"Collection issue: {issue?.ToJsonString()}");
                Console.WriteLine("\nUse --json for the full evidence report. No system configuration was changed.");
            }
            return 0;
        }
        catch (OperationCanceledException) { Console.Error.WriteLine("Collection cancelled."); return 130; }
        catch (Exception e) when (e is ArgumentException or JsonException or FileNotFoundException or DirectoryNotFoundException)
        { Console.Error.WriteLine($"{Tool.Name}: {e.Message}\nUse --help for usage."); return 2; }
        catch (Exception e)
        {
            if (json) Console.WriteLine(new JsonObject { ["schemaVersion"] = SchemaVersion, ["tool"] = Tool.Name, ["status"] = "failed", ["error"] = e.Message }.ToJsonString(J.Pretty));
            else Console.Error.WriteLine($"{Tool.Name}: collection failed: {e.Message}");
            return 3;
        }
    }
    public static Collection ReadSnapshot(JsonObject snapshot)
    {
        if (J.Number(snapshot, "schemaVersion") != SchemaVersion || J.Text(snapshot, "tool") != Tool.Name) throw new ArgumentException("Snapshot schema or tool does not match this application.");
        if (snapshot["evidence"] is not JsonObject evidence || snapshot["issues"] is not JsonArray issues || issues.Any(n => n is not JsonObject)) throw new ArgumentException("Snapshot must contain an evidence object and an issues array of objects.");
        Tool.ValidateEvidence(evidence);
        return new((JsonObject)evidence.DeepClone(), (JsonArray)issues.DeepClone());
    }
    public const string CommonHelp = "\nCommon options:\n  --json         Full structured report\n  --input FILE   Re-analyze a saved JSON report; no live queries\n  --help         Show usage\nExit: 0 report produced (including findings/partial evidence), 2 usage/snapshot error, 3 collection failed, 4 live collection requires Windows, 130 cancelled.\n";
}

public static class PowerShell
{
    public static async Task<Collection> Collect(Dictionary<string, string> environment, CancellationToken ct)
    {
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("Collector.ps1") ?? throw new InvalidOperationException("Collector resource is missing.");
        using var reader = new StreamReader(stream);
        var script = await reader.ReadToEndAsync(ct);
        var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe")) { RedirectStandardOutput = true, RedirectStandardError = true, StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8, UseShellExecute = false, CreateNoWindow = true };
        foreach (var arg in new[] { "-NoProfile", "-NonInteractive", "-EncodedCommand", Convert.ToBase64String(Encoding.Unicode.GetBytes(script)) }) start.ArgumentList.Add(arg);
        foreach (var item in environment) start.Environment[item.Key] = item.Value;
        using var process = Process.Start(start) ?? throw new InvalidOperationException("Could not start Windows PowerShell.");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(90));
        var output = ReadBounded(process.StandardOutput, timeout.Token); var errors = ReadBounded(process.StandardError, timeout.Token);
        try { await Task.WhenAll(process.WaitForExitAsync(timeout.Token), output, errors); }
        catch { try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { } if (ct.IsCancellationRequested) throw new OperationCanceledException(ct); throw new InvalidOperationException("Windows collector failed or exceeded its 90-second budget; no complete snapshot is available."); }
        if (process.ExitCode != 0) throw new InvalidOperationException($"Windows collector failed: {(await errors).Trim()}");
        var result = JsonNode.Parse(await output) as JsonObject ?? throw new InvalidOperationException("Windows collector did not return a JSON object.");
        if (result["evidence"] is not JsonObject evidence || result["issues"] is not JsonArray issues) throw new InvalidOperationException("Windows collector returned an invalid envelope.");
        if (!string.IsNullOrWhiteSpace(await errors)) issues.Add(new JsonObject { ["area"] = "powershell", ["message"] = (await errors).Trim() });
        return new(evidence, issues);
    }
    private static async Task<string> ReadBounded(StreamReader reader, CancellationToken ct)
    {
        var buffer = new char[4096]; var text = new StringBuilder(); int n;
        while ((n = await reader.ReadAsync(buffer.AsMemory(), ct)) > 0) { text.Append(buffer, 0, n); if (text.Length > 8 * 1024 * 1024) throw new InvalidOperationException("Collector output exceeded 8 MiB."); }
        return text.ToString();
    }
}
