using System.Globalization;
using System.Text.Json;
using Tamp.Sarif;

namespace Tamp.McpScanner;

/// <summary>
/// Normalises Cisco mcp-scanner JSON into a SARIF 2.1.0 <see cref="SarifLog"/>.
/// Pure: a string in, a log out — no process, no I/O — so the mapping is fully
/// unit-tested from saved fixtures (the same shape Cisco's static-manifest mode
/// produces).
/// </summary>
/// <remarks>
/// <para>
/// The scanner's JSON aggregates findings <em>per analyzer</em>: each scanned
/// item (tool / prompt / resource) carries a <c>findings</c> object keyed by
/// <c>&lt;analyzer&gt;_analyzer</c>, each block rolling up a severity, the
/// distinct <c>threat_names</c>, a <c>threat_summary</c>, and a
/// <c>total_findings</c> count. One SARIF result is emitted per
/// (item × analyzer × threat); an analyzer block that failed (status
/// <c>error</c>/<c>partial</c>) becomes an informational <c>level:none</c>
/// result so incomplete coverage stays visible rather than reading as "clean".
/// </para>
/// <para>
/// These findings are about an advertised <em>tool</em>, not a file, so each
/// carries a SARIF <see cref="SarifLogicalLocation"/> (never a synthesised file
/// path). Its <c>fullyQualifiedName</c> (server + item name) is also mirrored
/// into <c>partialFingerprints</c> so downstream dedup/correlation is stable.
/// </para>
/// </remarks>
public static class CiscoSarifMapper
{
    private const string DriverName = "mcp-scanner";
    private const string DriverInfoUri = "https://github.com/cisco-ai-defense/mcp-scanner";

    /// <summary>
    /// Map scanner JSON to a SARIF log. <paramref name="scanTarget"/> is a
    /// fallback server identity used when a result carries no server field of
    /// its own (e.g. the scanned URL or manifest path).
    /// </summary>
    /// <exception cref="InvalidDataException">The JSON is not parseable.</exception>
    public static SarifLog ToSarif(string scannerJson, string? scanTarget = null)
    {
        if (scannerJson is null) throw new ArgumentNullException(nameof(scannerJson));

        JsonDocument doc;
        try { doc = JsonDocument.Parse(scannerJson); }
        catch (JsonException ex) { throw new InvalidDataException($"mcp-scanner output is not valid JSON: {ex.Message}", ex); }

        using (doc)
        {
            var (items, topServer) = ExtractItems(doc.RootElement);
            var server = topServer ?? scanTarget;

            var results = new List<SarifResult>();
            var rules = new Dictionary<string, SarifRule>(StringComparer.Ordinal);

            foreach (var item in items)
                MapItem(item, server, results, rules);

            var run = new SarifRun
            {
                Tool = new SarifTool
                {
                    Driver = new SarifToolComponent
                    {
                        Name = DriverName,
                        InformationUri = DriverInfoUri,
                        Rules = rules.Count > 0 ? rules.Values.OrderBy(r => r.Id, StringComparer.Ordinal).ToList() : null,
                    },
                },
                Results = results,
            };

            return new SarifLog { Runs = [run] };
        }
    }

    // The CLI may emit either a bare array of result objects or an object that
    // wraps them under results/scan_results with a top-level target. Handle both.
    private static (List<JsonElement> Items, string? TopServer) ExtractItems(JsonElement root)
    {
        if (root.ValueKind == JsonValueKind.Array)
            return (root.EnumerateArray().ToList(), null);

        if (root.ValueKind == JsonValueKind.Object)
        {
            string? topServer = Str(root, "server_url") ?? Str(root, "scan_target") ?? Str(root, "server_source");
            foreach (var key in new[] { "results", "scan_results", "scanResults" })
            {
                if (root.TryGetProperty(key, out var arr) && arr.ValueKind == JsonValueKind.Array)
                    return (arr.EnumerateArray().ToList(), topServer);
            }

            // A single result object (one tool, unwrapped).
            if (root.TryGetProperty("findings", out _))
                return ([root], topServer);
        }

        return ([], null);
    }

    private static void MapItem(JsonElement item, string? fallbackServer, List<SarifResult> results, Dictionary<string, SarifRule> rules)
    {
        if (item.ValueKind != JsonValueKind.Object) return;
        if (!item.TryGetProperty("findings", out var findings) || findings.ValueKind != JsonValueKind.Object) return;

        var (itemName, kind, description) = ItemIdentity(item);
        var server = Str(item, "server_source") ?? Str(item, "server_name") ?? fallbackServer;
        var fqn = BuildFullyQualifiedName(server, itemName);

        foreach (var block in findings.EnumerateObject())
        {
            var analyzer = StripAnalyzerSuffix(block.Name);
            var data = block.Value;
            if (data.ValueKind != JsonValueKind.Object) continue;

            var status = Str(data, "status");
            var severityRaw = Str(data, "severity") ?? "UNKNOWN";
            var total = Int(data, "total_findings") ?? 0;
            var summary = Str(data, "threat_summary") ?? "";
            var threatNames = StringArray(data, "threat_names");

            // Analyzer that errored out → coverage gap, surfaced as informational.
            if (string.Equals(status, "error", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(status, "partial", StringComparison.OrdinalIgnoreCase))
            {
                var covRuleId = $"MCP-{analyzer.ToUpperInvariant()}-COVERAGE";
                rules.TryAdd(covRuleId, CoverageRule(covRuleId, analyzer));
                results.Add(CoverageResult(covRuleId, analyzer, summary, status!, itemName, kind, fqn, server, data));
                if (total == 0) continue; // errored with no findings — nothing else to emit
            }

            // SAFE / no findings → clean, nothing to report.
            if (total == 0 && !IsFindingSeverity(severityRaw)) continue;

            var level = SeverityToLevel(severityRaw);
            var threats = threatNames.Count > 0 ? threatNames : ["unspecified"];

            foreach (var threat in threats)
            {
                var ruleId = $"MCP-{analyzer.ToUpperInvariant()}-{Normalize(threat)}";
                rules.TryAdd(ruleId, ThreatRule(ruleId, analyzer, threat, level));
                results.Add(ThreatResult(ruleId, level, summary, threat, analyzer, total, severityRaw, itemName, kind, description, fqn, server, threatNames));
            }
        }
    }

    // ---- result builders -------------------------------------------------

    private static SarifResult ThreatResult(
        string ruleId, SarifLevel level, string summary, string threat, string analyzer, int total,
        string severityRaw, string itemName, string kind, string? description, string? fqn, string? server,
        IReadOnlyList<string> threatNames)
    {
        var text = summary.Length > 0
            ? summary
            : $"{analyzer} detected {threat.Replace('_', ' ')} on {kind} '{itemName}'.";

        var extra = new Dictionary<string, JsonElement>(StringComparer.Ordinal)
        {
            ["mcpAnalyzer"] = JsonValue(analyzer),
            ["mcpThreat"] = JsonValue(threat),
            ["mcpSeverity"] = JsonValue(severityRaw),
            ["mcpTotalFindings"] = JsonValue(total),
            ["mcpItemKind"] = JsonValue(kind),
        };
        if (server is not null) extra["mcpServer"] = JsonValue(server);
        if (description is not null) extra["mcpItemDescription"] = JsonValue(description);
        if (threatNames.Count > 0) extra["mcpThreatNames"] = JsonArray(threatNames);

        var fingerprints = new Dictionary<string, string>(StringComparer.Ordinal) { ["mcpThreat"] = threat };
        if (fqn is not null) fingerprints["mcpItem"] = fqn;

        return new SarifResult
        {
            RuleId = ruleId,
            Level = level,
            Message = new SarifMessage { Text = text },
            Locations = [LogicalLocation(itemName, fqn, kind)],
            Properties = new SarifPropertyBag { Tags = ["mcp", analyzer, kind, threat], AdditionalProperties = extra },
            PartialFingerprints = fingerprints,
        };
    }

    private static SarifResult CoverageResult(
        string ruleId, string analyzer, string summary, string status, string itemName, string kind, string? fqn,
        string? server, JsonElement data)
    {
        var text = $"Analyzer '{analyzer}' did not complete on {kind} '{itemName}' (status: {status})."
                 + (summary.Length > 0 ? $" {summary}" : "")
                 + " Coverage for this analyzer is incomplete — treat the item as unassessed by it, not clean.";

        var extra = new Dictionary<string, JsonElement>(StringComparer.Ordinal)
        {
            ["mcpAnalyzer"] = JsonValue(analyzer),
            ["mcpStatus"] = JsonValue(status),
            ["mcpItemKind"] = JsonValue(kind),
        };
        if (server is not null) extra["mcpServer"] = JsonValue(server);
        if (data.TryGetProperty("errors", out var errs) && errs.ValueKind == JsonValueKind.Array)
            extra["mcpErrors"] = errs.Clone();

        var fingerprints = new Dictionary<string, string>(StringComparer.Ordinal) { ["mcpCoverage"] = analyzer };
        if (fqn is not null) fingerprints["mcpItem"] = fqn;

        return new SarifResult
        {
            RuleId = ruleId,
            Level = SarifLevel.None,
            Message = new SarifMessage { Text = text },
            Locations = [LogicalLocation(itemName, fqn, kind)],
            Properties = new SarifPropertyBag { Tags = ["mcp", analyzer, "coverage"], AdditionalProperties = extra },
            PartialFingerprints = fingerprints,
        };
    }

    private static SarifLocation LogicalLocation(string itemName, string? fqn, string kind) => new()
    {
        LogicalLocations =
        [
            new SarifLogicalLocation
            {
                Name = itemName,
                FullyQualifiedName = fqn,
                Kind = kind,
            },
        ],
    };

    // ---- rule builders ---------------------------------------------------

    private static SarifRule ThreatRule(string ruleId, string analyzer, string threat, SarifLevel level) => new()
    {
        Id = ruleId,
        Name = $"{analyzer}/{threat}",
        ShortDescription = new SarifMultiformatMessage { Text = $"{analyzer}: {threat.Replace('_', ' ')}" },
        HelpUri = DriverInfoUri,
        DefaultConfiguration = new SarifReportingConfiguration { Level = level },
        Properties = new SarifPropertyBag { Tags = ["mcp", analyzer, threat] },
    };

    private static SarifRule CoverageRule(string ruleId, string analyzer) => new()
    {
        Id = ruleId,
        Name = $"{analyzer}/coverage",
        ShortDescription = new SarifMultiformatMessage { Text = $"{analyzer}: analyzer did not complete (coverage gap)" },
        HelpUri = DriverInfoUri,
        DefaultConfiguration = new SarifReportingConfiguration { Level = SarifLevel.None },
        Properties = new SarifPropertyBag { Tags = ["mcp", analyzer, "coverage"] },
    };

    // ---- small helpers ---------------------------------------------------

    private static (string Name, string Kind, string? Description) ItemIdentity(JsonElement item)
    {
        var type = Str(item, "item_type");
        if (type == "prompt" || item.TryGetProperty("prompt_name", out _))
            return (Str(item, "prompt_name") ?? "(prompt)", "mcpPrompt", Str(item, "prompt_description"));
        if (type == "resource" || item.TryGetProperty("resource_uri", out _))
            return (Str(item, "resource_uri") ?? Str(item, "resource_name") ?? "(resource)", "mcpResource", Str(item, "resource_name"));
        return (Str(item, "tool_name") ?? "(tool)", "mcpTool", Str(item, "tool_description"));
    }

    private static string? BuildFullyQualifiedName(string? server, string itemName)
    {
        if (string.IsNullOrEmpty(server)) return itemName.Length > 0 ? itemName : null;
        return $"{server.TrimEnd('/')}/{itemName}";
    }

    private static string StripAnalyzerSuffix(string key) =>
        key.EndsWith("_analyzer", StringComparison.Ordinal) ? key[..^"_analyzer".Length] : key;

    private static bool IsFindingSeverity(string severity) =>
        severity.ToUpperInvariant() is "HIGH" or "MEDIUM" or "LOW" or "INFO";

    private static SarifLevel SeverityToLevel(string severity) => severity.ToUpperInvariant() switch
    {
        "HIGH" => SarifLevel.Error,
        "MEDIUM" => SarifLevel.Warning,
        "LOW" => SarifLevel.Note,
        "INFO" => SarifLevel.Note,
        _ => SarifLevel.None,
    };

    private static string Normalize(string s)
    {
        var chars = s.Trim().ToUpperInvariant().Select(c => char.IsLetterOrDigit(c) ? c : '_').ToArray();
        var collapsed = new string(chars).Trim('_');
        return collapsed.Length > 0 ? collapsed : "UNSPECIFIED";
    }

    private static string? Str(JsonElement e, string prop) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(prop, out var p) && p.ValueKind == JsonValueKind.String
            ? p.GetString()
            : null;

    private static int? Int(JsonElement e, string prop) =>
        e.TryGetProperty(prop, out var p) && p.ValueKind == JsonValueKind.Number && p.TryGetInt32(out var i) ? i : null;

    private static IReadOnlyList<string> StringArray(JsonElement e, string prop)
    {
        if (!e.TryGetProperty(prop, out var arr) || arr.ValueKind != JsonValueKind.Array) return [];
        var list = new List<string>();
        foreach (var el in arr.EnumerateArray())
            if (el.ValueKind == JsonValueKind.String && el.GetString() is { Length: > 0 } s)
                list.Add(s);
        return list;
    }

    private static JsonElement JsonValue(string s) => JsonSerializer.SerializeToElement(s);
    private static JsonElement JsonValue(int i) => JsonSerializer.SerializeToElement(i);
    private static JsonElement JsonArray(IReadOnlyList<string> items) => JsonSerializer.SerializeToElement(items);
}
