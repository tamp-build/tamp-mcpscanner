using Tamp.Sarif;

namespace Tamp.McpScanner;

/// <summary>
/// An <see cref="IFindingSource"/> that runs Cisco mcp-scanner and returns its
/// findings as a normalised SARIF 2.1.0 <see cref="SarifLog"/>. Slots into the
/// Tamp security chain (merge, dedup, DefectDojo/Dependency-Track push,
/// tamp-findings) exactly like the OpenGrep and Trivy sources.
/// </summary>
/// <remarks>
/// <para><b>Noisy by nature.</b> MCP pattern detectors have a high false-positive
/// rate (a 2026 audit measured ~78% on the pattern layer). This source is built
/// to produce <em>nightly, non-blocking evidence</em> for tamp-findings to triage
/// and trend — it is not a per-push gate. Do not fail a build on its output.</para>
/// <para>The scanner's non-zero exit is not treated as failure on its own: Cisco
/// does not document exit codes, and a non-zero exit with parseable JSON means
/// "findings". A failure is only raised when the scanner produced no parseable
/// output at all.</para>
/// </remarks>
public sealed class McpScanSource : IFindingSource
{
    private readonly McpScanSettingsBase _settings;
    private readonly IMcpScannerProcess _process;

    /// <param name="settings">The configured scan (mode + analyzers + rules).</param>
    /// <param name="process">Process runner; defaults to the real mcp-scanner via <see cref="ProcessRunner"/>.</param>
    public McpScanSource(McpScanSettingsBase settings, IMcpScannerProcess? process = null)
    {
        _settings = settings ?? throw new ArgumentNullException(nameof(settings));
        _process = process ?? new DefaultMcpScannerProcess();
    }

    /// <inheritdoc/>
    public Task<SarifLog> ScanAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        string? rulesDir = null;
        string? outputFile = null;
        try
        {
            rulesDir = ResolveRulesDir();
            outputFile = Path.Combine(Path.GetTempPath(), "tamp-mcp-scan-" + Guid.NewGuid().ToString("N") + ".json");

            var plan = _settings.BuildPlan(rulesDir, outputFile);
            var capture = _process.Run(plan);

            var json = ReadJson(outputFile, capture);
            if (string.IsNullOrWhiteSpace(json))
            {
                throw new InvalidDataException(
                    $"mcp-scanner produced no parseable output (exit {capture.ExitCode}). " +
                    (capture.StderrText.Length > 0 ? "Stderr: " + capture.StderrText : "No stderr."));
            }

            var log = CiscoSarifMapper.ToSarif(json, _settings.ScanTarget);
            return Task.FromResult(log);
        }
        finally
        {
            TryDeleteFile(outputFile);
            TryDeleteDir(rulesDir);
        }
    }

    private string? ResolveRulesDir()
    {
        if (!string.IsNullOrEmpty(_settings.CustomRulesPath)) return _settings.CustomRulesPath;
        if (_settings.Stack is { } stack) return StackRules.MaterializeToTemp(stack);
        return null;
    }

    private static string ReadJson(string outputFile, CaptureResult capture)
    {
        if (File.Exists(outputFile))
        {
            var fromFile = File.ReadAllText(outputFile);
            if (!string.IsNullOrWhiteSpace(fromFile)) return fromFile;
        }
        // Fall back to stdout (e.g. a fake process, or a build of the CLI that
        // ignored --output). The scanner's JSON is the payload either way.
        return capture.StdoutText;
    }

    // Only the temp rules dir we created is ours to delete — never a caller's CustomRulesPath.
    private void TryDeleteDir(string? dir)
    {
        if (dir is null || dir == _settings.CustomRulesPath) return;
        try { if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true); }
        catch { /* best-effort temp cleanup */ }
    }

    private static void TryDeleteFile(string? file)
    {
        if (file is null) return;
        try { if (File.Exists(file)) File.Delete(file); }
        catch { /* best-effort temp cleanup */ }
    }
}
