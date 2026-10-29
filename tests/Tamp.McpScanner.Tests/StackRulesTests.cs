using Xunit;

namespace Tamp.McpScanner.Tests;

public class StackRulesTests
{
    [Fact]
    public void Common_pack_contains_the_full_vendored_rule_set()
    {
        var files = StackRules.PackFiles(McpStack.Common);
        Assert.Contains("credential_harvesting.yara", files);
        Assert.Contains("tool_poisoning.yara", files);
        // The complete base is 10 Cisco rules.
        Assert.Equal(10, files.Count);
    }

    [Fact]
    public void DotNet_pack_overlays_only_the_tuned_rules()
    {
        var files = StackRules.PackFiles(McpStack.DotNet);
        Assert.Contains("credential_harvesting.yara", files);
        // The overlay is a subset — it does not re-ship untuned rules.
        Assert.True(files.Count < 10);
    }

    [Fact]
    public void Materialising_dotnet_yields_the_complete_set_with_the_overlay_winning()
    {
        var dir = Path.Combine(Path.GetTempPath(), "tamp-mcp-rules-test-" + Guid.NewGuid().ToString("N"));
        try
        {
            StackRules.Materialize(McpStack.DotNet, dir);

            var onDisk = Directory.GetFiles(dir, "*.yara").Select(Path.GetFileName).ToList();
            // Base rules are all present (overlay completed, not replaced).
            Assert.Equal(10, onDisk.Count);
            Assert.Contains("tool_poisoning.yara", onDisk);

            // The credential_harvesting rule is the .NET-tuned version.
            var cred = File.ReadAllText(Path.Combine(dir, "credential_harvesting.yara"));
            Assert.Contains("dotnet_config_idioms", cred);
            Assert.Contains(".NET tuning by Tamp Project", cred);
        }
        finally
        {
            if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Common_materialisation_is_the_untuned_base()
    {
        var dir = Path.Combine(Path.GetTempPath(), "tamp-mcp-rules-test-" + Guid.NewGuid().ToString("N"));
        try
        {
            StackRules.Materialize(McpStack.Common, dir);
            var cred = File.ReadAllText(Path.Combine(dir, "credential_harvesting.yara"));
            Assert.DoesNotContain("dotnet_config_idioms", cred);
        }
        finally
        {
            if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true);
        }
    }
}
