using Xunit;

namespace Tamp.McpScanner.Tests;

public class McpScanSourceTests
{
    [Fact]
    public async Task Remote_scan_builds_the_right_plan_and_normalises_output()
    {
        var fake = new FakeMcpScannerProcess(TestData.Load("tool_with_findings.json"));
        var source = McpScanner.ScanRemote(s =>
        {
            s.ServerUrl = "https://mcp.example.com/mcp";
            s.BearerToken = new Secret("mcp", "super-secret-token-value");
        }, fake);

        var log = await source.ScanAsync();

        Assert.Equal(2, log.Runs[0].Results!.Count);

        var args = fake.LastPlan!.Arguments;
        Assert.Equal("remote", args[0]);
        Assert.Contains("--server-url", args);
        Assert.Contains("https://mcp.example.com/mcp", args);
        Assert.Contains("--analyzers", args);
        Assert.Contains("yara,readiness,prompt_defense", args);
        Assert.Contains("--output", args);
    }

    [Fact]
    public async Task Offline_default_is_a_safe_capability_tier()
    {
        var fake = new FakeMcpScannerProcess(TestData.Load("all_safe.json"));
        var source = McpScanner.ScanRemote(s => s.ServerUrl = "https://x/mcp", fake);
        await source.ScanAsync();
        Assert.Equal(CapabilityTier.Safe, fake.LastPlan!.RequiredCapability);
    }

    [Fact]
    public async Task Bearer_token_is_registered_as_a_secret_for_redaction()
    {
        var fake = new FakeMcpScannerProcess(TestData.Load("all_safe.json"));
        var token = new Secret("mcp", "super-secret-token-value");
        var source = McpScanner.ScanRemote(s => { s.ServerUrl = "https://x/mcp"; s.BearerToken = token; }, fake);
        await source.ScanAsync();
        Assert.Contains(fake.LastPlan!.Secrets, x => ReferenceEquals(x, token));
    }

    [Fact]
    public async Task Enabling_an_egressing_analyzer_marks_the_command_side_effectful()
    {
        var fake = new FakeMcpScannerProcess(TestData.Load("all_safe.json"));
        var source = McpScanner.ScanRemote(s =>
        {
            s.ServerUrl = "https://x/mcp";
            s.Analyzers.Add(McpAnalyzer.Api);
            s.ApiKey = new Secret("cisco", "cisco-key");
        }, fake);
        await source.ScanAsync();
        Assert.Equal(CapabilityTier.SideEffectful, fake.LastPlan!.RequiredCapability);
    }

    [Fact]
    public async Task Stack_selection_materialises_a_rules_dir_and_passes_rules_path()
    {
        var fake = new FakeMcpScannerProcess(TestData.Load("all_safe.json"));
        var source = McpScanner.ScanStatic(s => { s.ToolsPath = "tools.json"; s.Stack = McpStack.DotNet; }, fake);

        await source.ScanAsync();

        Assert.NotNull(fake.RulesPathSeen);
        Assert.True(fake.RulesDirExistedAtRun, "rules dir should exist at scan time");
        // Cleaned up afterwards (temp dir we created).
        Assert.False(Directory.Exists(fake.RulesPathSeen!), "temp rules dir should be removed after the scan");
    }

    [Fact]
    public async Task Static_scan_requires_at_least_one_manifest()
    {
        var fake = new FakeMcpScannerProcess("[]");
        var source = McpScanner.ScanStatic(_ => { }, fake);
        await Assert.ThrowsAsync<InvalidOperationException>(() => source.ScanAsync());
    }

    [Fact]
    public async Task Empty_output_is_a_failure_not_a_clean_scan()
    {
        var fake = new FakeMcpScannerProcess("", exitCode: 2);
        var source = McpScanner.ScanRemote(s => s.ServerUrl = "https://x/mcp", fake);
        await Assert.ThrowsAsync<InvalidDataException>(() => source.ScanAsync());
    }
}
