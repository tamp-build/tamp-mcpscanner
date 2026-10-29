namespace Tamp.McpScanner;

/// <summary>
/// Cisco mcp-scanner analyzers. The three offline ones — <see cref="Yara"/>,
/// <see cref="Readiness"/>, <see cref="PromptDefense"/> — need no key and are
/// the Tamp default (the air-gapped set). The rest reach a model or a vendor
/// service and are opt-in:
/// <list type="bullet">
///   <item><see cref="Llm"/> — behavioural/source analysis against an LLM. Point it at a
///   local endpoint (Ollama) to stay on-prem.</item>
///   <item><see cref="Api"/> — Cisco AI Defense. Needs a Cisco API key and egresses.</item>
/// </list>
/// </summary>
/// <remarks>
/// The wire name (what goes after <c>--analyzers</c>) is the lowercase token
/// produced by the internal <c>WireName</c> extension, not the enum spelling.
/// </remarks>
public enum McpAnalyzer
{
    /// <summary>Local YARA pattern rules over tool descriptions. Offline. Tamp default.</summary>
    Yara,

    /// <summary>Local operational-readiness heuristics (timeouts, capability bounds, error schema). Offline. Tamp default.</summary>
    Readiness,

    /// <summary>Local regex over known prompt-injection attack vectors. Offline. Tamp default.</summary>
    PromptDefense,

    /// <summary>Behavioural / source analysis via an LLM. On-prem if pointed at a local endpoint; opt-in.</summary>
    Llm,

    /// <summary>Cisco AI Defense classifier. Needs a vendor key and egresses; opt-in.</summary>
    Api,
}

internal static class McpAnalyzerExtensions
{
    /// <summary>The <c>--analyzers</c> wire token for this analyzer.</summary>
    public static string WireName(this McpAnalyzer analyzer) => analyzer switch
    {
        McpAnalyzer.Yara => "yara",
        McpAnalyzer.Readiness => "readiness",
        McpAnalyzer.PromptDefense => "prompt_defense",
        McpAnalyzer.Llm => "llm",
        McpAnalyzer.Api => "api",
        _ => throw new ArgumentOutOfRangeException(nameof(analyzer), analyzer, "Unknown analyzer."),
    };

    /// <summary>True when the analyzer runs entirely locally (no key, no egress).</summary>
    public static bool IsOffline(this McpAnalyzer analyzer) =>
        analyzer is McpAnalyzer.Yara or McpAnalyzer.Readiness or McpAnalyzer.PromptDefense;
}
