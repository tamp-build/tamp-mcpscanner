namespace Tamp.McpScanner;

/// <summary>
/// Common settings for every mcp-scanner scan mode. Subclasses add the
/// subcommand verb and its mode-specific target. The default analyzer set is
/// the three offline ones (<see cref="McpAnalyzer.Yara"/>,
/// <see cref="McpAnalyzer.Readiness"/>, <see cref="McpAnalyzer.PromptDefense"/>)
/// — no key, no egress.
/// </summary>
public abstract class McpScanSettingsBase
{
    /// <summary>The mcp-scanner executable (on PATH, or an absolute path). Defaults to <c>mcp-scanner</c>.</summary>
    public string Executable { get; set; } = "mcp-scanner";

    /// <summary>Analyzers to run (<c>--analyzers</c>). Defaults to the offline set.</summary>
    public List<McpAnalyzer> Analyzers { get; } = [McpAnalyzer.Yara, McpAnalyzer.Readiness, McpAnalyzer.PromptDefense];

    /// <summary>Minimum severity to include (<c>--severity-filter</c>), e.g. "high". Null = scanner default.</summary>
    public string? SeverityFilter { get; set; }

    /// <summary>
    /// A tuned per-stack YARA rule pack to use instead of the generic rules.
    /// Mutually complementary with <see cref="CustomRulesPath"/> (which wins if
    /// both are set). See <see cref="McpStack"/> and docs/stack-rules.md.
    /// </summary>
    public McpStack? Stack { get; set; }

    /// <summary>
    /// An explicit custom YARA rules directory (<c>--rules-path</c>), overriding
    /// <see cref="Stack"/>. The directory REPLACES the scanner's built-in rules,
    /// so it must be a complete rule set.
    /// </summary>
    public string? CustomRulesPath { get; set; }

    /// <summary>Endpoint for the LLM analyzer (<c>--endpoint-url</c>), e.g. a local Ollama URL. Keeps behavioural analysis on-prem.</summary>
    public string? LlmEndpointUrl { get; set; }

    /// <summary>Key for the LLM analyzer (<c>--llm-api-key</c>). Only needed when <see cref="McpAnalyzer.Llm"/> is enabled.</summary>
    public Secret? LlmApiKey { get; set; }

    /// <summary>Key for the Cisco AI Defense <see cref="McpAnalyzer.Api"/> analyzer (<c>--api-key</c>). Egresses; opt-in.</summary>
    public Secret? ApiKey { get; set; }

    /// <summary>Working directory for the scanner process.</summary>
    public string? WorkingDirectory { get; set; }

    /// <summary>Extra environment variables for the scanner process.</summary>
    public Dictionary<string, string> EnvironmentVariables { get; } = [];

    /// <summary>The subcommand verb (e.g. "remote", "static") and its mode-specific arguments.</summary>
    protected abstract IEnumerable<string> BuildSubcommandArguments();

    /// <summary>
    /// A human-meaningful identity for what was scanned (URL, manifest path) —
    /// used as the fallback server in logical-location identity when a result
    /// carries none of its own.
    /// </summary>
    public abstract string ScanTarget { get; }

    /// <summary>The <see cref="Secret"/>s this scan reveals, for the runner's redaction table.</summary>
    internal virtual IEnumerable<Secret> Secrets()
    {
        if (LlmApiKey is not null) yield return LlmApiKey;
        if (ApiKey is not null) yield return ApiKey;
    }

    /// <summary>
    /// Build the full <see cref="CommandPlan"/>. <paramref name="resolvedRulesPath"/>
    /// is the directory the source materialised for <see cref="Stack"/> /
    /// <see cref="CustomRulesPath"/> (null when neither is set);
    /// <paramref name="outputFile"/> is where the scanner writes its JSON.
    /// </summary>
    internal CommandPlan BuildPlan(string? resolvedRulesPath, string outputFile)
    {
        var args = new List<string>();
        args.AddRange(BuildSubcommandArguments());

        if (Analyzers.Count > 0)
        {
            args.Add("--analyzers");
            args.Add(string.Join(",", Analyzers.Select(a => a.WireName())));
        }

        if (!string.IsNullOrEmpty(SeverityFilter))
        {
            args.Add("--severity-filter");
            args.Add(SeverityFilter);
        }

        if (!string.IsNullOrEmpty(resolvedRulesPath))
        {
            args.Add("--rules-path");
            args.Add(resolvedRulesPath);
        }

        if (!string.IsNullOrEmpty(LlmEndpointUrl))
        {
            args.Add("--endpoint-url");
            args.Add(LlmEndpointUrl);
        }

        if (LlmApiKey is not null)
        {
            args.Add("--llm-api-key");
            args.Add(LlmApiKey.Reveal());
        }

        if (ApiKey is not null)
        {
            args.Add("--api-key");
            args.Add(ApiKey.Reveal());
        }

        args.Add("--output");
        args.Add(outputFile);

        // Any analyzer that reaches a model or vendor service makes this a
        // side-effectful (egressing) command; the offline default stays Safe.
        var egresses = Analyzers.Any(a => !a.IsOffline()) || ApiKey is not null || LlmApiKey is not null;

        return new CommandPlan
        {
            Executable = Executable,
            Arguments = args,
            WorkingDirectory = WorkingDirectory,
            Environment = new Dictionary<string, string>(EnvironmentVariables),
            Secrets = Secrets().ToList(),
            RequiredCapability = egresses ? CapabilityTier.SideEffectful : CapabilityTier.Safe,
        };
    }
}

/// <summary>Scan a running MCP server over HTTP/SSE (<c>mcp-scanner remote</c>).</summary>
public sealed class McpRemoteScanSettings : McpScanSettingsBase
{
    /// <summary>The MCP server URL (<c>--server-url</c>). Required.</summary>
    public string ServerUrl { get; set; } = "";

    /// <summary>Bearer token for the server (<c>--bearer-token</c>), typed for redaction.</summary>
    public Secret? BearerToken { get; set; }

    /// <summary>Extra request headers (<c>--header</c>, repeated), each "Name: value".</summary>
    public List<string> Headers { get; } = [];

    /// <inheritdoc/>
    public override string ScanTarget => ServerUrl;

    internal override IEnumerable<Secret> Secrets()
    {
        foreach (var s in base.Secrets()) yield return s;
        if (BearerToken is not null) yield return BearerToken;
    }

    protected override IEnumerable<string> BuildSubcommandArguments()
    {
        if (string.IsNullOrEmpty(ServerUrl)) throw new InvalidOperationException("McpRemoteScanSettings.ServerUrl is required.");
        yield return "remote";
        yield return "--server-url";
        yield return ServerUrl;
        if (BearerToken is not null)
        {
            yield return "--bearer-token";
            yield return BearerToken.Reveal();
        }
        foreach (var h in Headers)
        {
            yield return "--header";
            yield return h;
        }
    }
}

/// <summary>
/// Scan a pre-generated tool/prompt/resource manifest (<c>mcp-scanner static</c>)
/// — the air-gapped path, and the one that needs no live server (ideal for
/// fixtures and tests). At least one of the three paths must be set.
/// </summary>
public sealed class McpStaticScanSettings : McpScanSettingsBase
{
    /// <summary>Path to a tools manifest JSON (a saved <c>tools/list</c> response). <c>--tools</c>.</summary>
    public string? ToolsPath { get; set; }

    /// <summary>Path to a prompts manifest JSON. <c>--prompts</c>.</summary>
    public string? PromptsPath { get; set; }

    /// <summary>Path to a resources manifest JSON. <c>--resources</c>.</summary>
    public string? ResourcesPath { get; set; }

    /// <inheritdoc/>
    public override string ScanTarget => ToolsPath ?? PromptsPath ?? ResourcesPath ?? "(static)";

    protected override IEnumerable<string> BuildSubcommandArguments()
    {
        if (string.IsNullOrEmpty(ToolsPath) && string.IsNullOrEmpty(PromptsPath) && string.IsNullOrEmpty(ResourcesPath))
            throw new InvalidOperationException("McpStaticScanSettings requires at least one of ToolsPath/PromptsPath/ResourcesPath.");
        yield return "static";
        if (!string.IsNullOrEmpty(ToolsPath)) { yield return "--tools"; yield return ToolsPath; }
        if (!string.IsNullOrEmpty(PromptsPath)) { yield return "--prompts"; yield return PromptsPath; }
        if (!string.IsNullOrEmpty(ResourcesPath)) { yield return "--resources"; yield return ResourcesPath; }
    }
}

/// <summary>
/// Scan the MCP servers declared in a client config file (<c>mcp-scanner
/// --config-path</c>) — covers stdio servers, which Cisco reaches through the
/// config rather than a direct command.
/// </summary>
public sealed class McpConfigScanSettings : McpScanSettingsBase
{
    /// <summary>Path to an MCP client config file (<c>--config-path</c>). Required.</summary>
    public string ConfigPath { get; set; } = "";

    /// <inheritdoc/>
    public override string ScanTarget => ConfigPath;

    protected override IEnumerable<string> BuildSubcommandArguments()
    {
        if (string.IsNullOrEmpty(ConfigPath)) throw new InvalidOperationException("McpConfigScanSettings.ConfigPath is required.");
        yield return "--config-path";
        yield return ConfigPath;
    }
}
