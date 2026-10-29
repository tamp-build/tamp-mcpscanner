namespace Tamp.McpScanner.Tests;

/// <summary>Loads a JSON fixture copied next to the test assembly.</summary>
internal static class TestData
{
    public static string Load(string fixtureName)
    {
        var path = Path.Combine(AppContext.BaseDirectory, "fixtures", fixtureName);
        return File.ReadAllText(path);
    }
}

/// <summary>
/// An <see cref="IMcpScannerProcess"/> that records the plan it was handed and
/// returns canned scanner JSON on stdout — no binary, no network. The source
/// reads from stdout when the (never-written) --output file is absent.
/// </summary>
internal sealed class FakeMcpScannerProcess : IMcpScannerProcess
{
    private readonly string _stdoutJson;
    private readonly int _exitCode;

    public FakeMcpScannerProcess(string stdoutJson, int exitCode = 0)
    {
        _stdoutJson = stdoutJson;
        _exitCode = exitCode;
    }

    public CommandPlan? LastPlan { get; private set; }
    public string? RulesPathSeen { get; private set; }
    public bool RulesDirExistedAtRun { get; private set; }

    public CaptureResult Run(CommandPlan plan)
    {
        LastPlan = plan;

        var args = plan.Arguments;
        var idx = args.ToList().IndexOf("--rules-path");
        if (idx >= 0 && idx + 1 < args.Count)
        {
            RulesPathSeen = args[idx + 1];
            RulesDirExistedAtRun = Directory.Exists(RulesPathSeen);
        }

        var lines = _stdoutJson
            .Split('\n')
            .Select(l => new OutputLine(OutputType.Stdout, l.TrimEnd('\r')))
            .ToList();
        return new CaptureResult(_exitCode, lines);
    }
}
