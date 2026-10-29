namespace Tamp.McpScanner;

/// <summary>
/// The seam between <see cref="McpScanSource"/> and the actual <c>mcp-scanner</c>
/// process. The default implementation dispatches the <see cref="CommandPlan"/>
/// through Tamp's <see cref="ProcessRunner"/>; tests substitute a fake that
/// returns canned scanner JSON, so the whole normalisation path is exercised
/// with no binary, network, or MCP server.
/// </summary>
public interface IMcpScannerProcess
{
    /// <summary>Run the plan and capture its output.</summary>
    CaptureResult Run(CommandPlan plan);
}

/// <summary>
/// Default <see cref="IMcpScannerProcess"/>: capture the child's stdout/stderr
/// via <see cref="ProcessRunner.Capture(CommandPlan, System.IO.TextWriter?, System.IO.TextWriter?)"/>.
/// </summary>
/// <remarks>
/// Capture (not Execute) because the wrapper reads the scanner's JSON from
/// stdout when no <c>--output</c> file is used. The non-zero exit is NOT treated
/// as a crash: Cisco does not document its exit codes, and a non-zero exit with
/// parseable JSON means "findings", not "tool failure" (see <see cref="McpScanSource"/>).
/// </remarks>
public sealed class DefaultMcpScannerProcess : IMcpScannerProcess
{
    /// <inheritdoc/>
    public CaptureResult Run(CommandPlan plan) => ProcessRunner.Capture(plan);
}
