namespace Tamp.McpScanner;

/// <summary>
/// A technology stack an MCP server is implemented in, selecting a tuned YARA
/// rule pack. Cisco's generic rules match regexes over tool <em>descriptions</em>
/// and bake in shell/Python idioms, so a .NET server whose tool descriptions
/// legitimately mention NuGet restore steps, <c>IConfiguration</c>, or
/// <c>System.IO</c> can trip <c>command_injection</c> / <c>code_execution</c> /
/// <c>credential_harvesting</c>. A stack pack is a complete rule set — the base
/// rules with per-stack idioms added to the over-firing rules' negative
/// conditions — materialised and passed via <c>--rules-path</c>.
/// </summary>
/// <remarks>
/// See <see cref="StackRules"/> and docs/stack-rules.md. <see cref="Common"/> is
/// the untuned base; the others overlay stack tuning on top of it.
/// </remarks>
public enum McpStack
{
    /// <summary>The untuned base rule set (the Tamp-maintained copy of the generic rules).</summary>
    Common,

    /// <summary>.NET / NuGet MCP servers (e.g. the ModelContextProtocol C# SDK, <c>tamp mcp</c>).</summary>
    DotNet,

    /// <summary>TypeScript / npm MCP servers.</summary>
    TypeScript,

    /// <summary>Python / PyPI MCP servers.</summary>
    Python,
}

internal static class McpStackExtensions
{
    /// <summary>The embedded-resource folder name for this stack's pack.</summary>
    public static string PackName(this McpStack stack) => stack switch
    {
        McpStack.Common => "common",
        McpStack.DotNet => "dotnet",
        McpStack.TypeScript => "typescript",
        McpStack.Python => "python",
        _ => throw new ArgumentOutOfRangeException(nameof(stack), stack, "Unknown stack."),
    };
}
