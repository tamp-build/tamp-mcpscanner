using Tamp.Sarif;

namespace Tamp.McpScanner;

/// <summary>
/// Tamp wrapper for Cisco's <c>mcp-scanner</c>. Scans MCP servers for
/// tool-poisoning / prompt-injection / credential-harvesting and related
/// threats, and normalises the scanner's JSON into SARIF 2.1.0 so MCP findings
/// flow through the existing Tamp security chain.
/// <list type="bullet">
///   <item><see cref="ScanRemote"/> — a running server over HTTP/SSE.</item>
///   <item><see cref="ScanStatic"/> — a pre-generated tool/prompt/resource manifest (air-gapped; the fixture path).</item>
///   <item><see cref="ScanConfig"/> — the MCP servers declared in a client config file (covers stdio servers).</item>
/// </list>
/// Each returns an <see cref="IFindingSource"/>; call <see cref="IFindingSource.ScanAsync"/>
/// to run the scan and get the normalised <see cref="SarifLog"/>.
/// </summary>
/// <remarks>
/// Offline analyzers (yara, readiness, prompt_defense) by default — no key, no
/// egress. MCP detectors are noisy (~78% false positives on the pattern layer
/// in a 2026 audit), so this is designed as nightly, non-blocking evidence for
/// tamp-findings, <b>not</b> a per-push gate. See README "False positives" and
/// docs/stack-rules.md for the stack-tuned rule packs that cut idiomatic FPs.
/// </remarks>
public static class McpScanner
{
    /// <summary>Scan a running MCP server over HTTP/SSE.</summary>
    public static McpScanSource ScanRemote(Action<McpRemoteScanSettings> configure, IMcpScannerProcess? process = null)
        => Build(configure, process);

    /// <summary>Scan a pre-generated tool/prompt/resource manifest — no live server needed.</summary>
    public static McpScanSource ScanStatic(Action<McpStaticScanSettings> configure, IMcpScannerProcess? process = null)
        => Build(configure, process);

    /// <summary>Scan the MCP servers declared in a client config file (stdio and otherwise).</summary>
    public static McpScanSource ScanConfig(Action<McpConfigScanSettings> configure, IMcpScannerProcess? process = null)
        => Build(configure, process);

    private static McpScanSource Build<TSettings>(Action<TSettings> configure, IMcpScannerProcess? process)
        where TSettings : McpScanSettingsBase, new()
    {
        if (configure is null) throw new ArgumentNullException(nameof(configure));
        var settings = new TSettings();
        configure(settings);
        return new McpScanSource(settings, process);
    }
}
