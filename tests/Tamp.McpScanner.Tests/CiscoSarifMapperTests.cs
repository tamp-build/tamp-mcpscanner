using Tamp.Sarif;
using Xunit;

namespace Tamp.McpScanner.Tests;

public class CiscoSarifMapperTests
{
    private static SarifLog Map(string fixture) => CiscoSarifMapper.ToSarif(TestData.Load(fixture));

    [Fact]
    public void Driver_is_mcp_scanner()
    {
        var run = Map("tool_with_findings.json").Runs[0];
        Assert.Equal("mcp-scanner", run.Tool.Driver.Name);
    }

    [Fact]
    public void One_result_per_analyzer_block_with_findings_safe_blocks_skipped()
    {
        // yara (1 threat) + prompt_defense (1 threat) = 2 results; the SAFE
        // readiness block contributes nothing.
        var results = Map("tool_with_findings.json").Runs[0].Results!;
        Assert.Equal(2, results.Count);
        Assert.Contains(results, r => r.RuleId == "MCP-YARA-TOOL_POISONING");
        Assert.Contains(results, r => r.RuleId == "MCP-PROMPT_DEFENSE-PROMPT_INJECTION");
    }

    [Fact]
    public void Severity_maps_high_to_error_and_medium_to_warning()
    {
        var results = Map("tool_with_findings.json").Runs[0].Results!;
        Assert.Equal(SarifLevel.Error, results.Single(r => r.RuleId == "MCP-YARA-TOOL_POISONING").Level);
        Assert.Equal(SarifLevel.Warning, results.Single(r => r.RuleId == "MCP-PROMPT_DEFENSE-PROMPT_INJECTION").Level);
    }

    [Fact]
    public void Finding_carries_a_logical_location_not_a_physical_one()
    {
        var r = Map("tool_with_findings.json").Runs[0].Results!.First(x => x.RuleId == "MCP-YARA-TOOL_POISONING");
        var loc = Assert.Single(r.Locations!);
        Assert.Null(loc.PhysicalLocation);
        var logical = Assert.Single(loc.LogicalLocations!);
        Assert.Equal("query_database", logical.Name);
        Assert.Equal("https://mcp.example.com/mcp/query_database", logical.FullyQualifiedName);
        Assert.Equal("mcpTool", logical.Kind);
    }

    [Fact]
    public void Fully_qualified_name_is_mirrored_into_partial_fingerprints()
    {
        var r = Map("tool_with_findings.json").Runs[0].Results!.First(x => x.RuleId == "MCP-YARA-TOOL_POISONING");
        Assert.Equal("https://mcp.example.com/mcp/query_database", r.PartialFingerprints!["mcpItem"]);
        Assert.Equal("tool_poisoning", r.PartialFingerprints["mcpThreat"]);
    }

    [Fact]
    public void Message_and_properties_carry_the_summary_and_context()
    {
        var r = Map("tool_with_findings.json").Runs[0].Results!.First(x => x.RuleId == "MCP-YARA-TOOL_POISONING");
        Assert.Equal("Detected 1 threat: tool poisoning", r.Message.Text);
        Assert.Contains("mcp", r.Properties!.Tags!);
        Assert.Contains("yara", r.Properties.Tags!);
        Assert.Equal("yara", r.Properties.AdditionalProperties!["mcpAnalyzer"].GetString());
    }

    [Fact]
    public void Rules_are_declared_for_every_emitted_rule_id()
    {
        var run = Map("tool_with_findings.json").Runs[0];
        var ruleIds = run.Tool.Driver.Rules!.Select(r => r.Id).ToHashSet();
        Assert.Contains("MCP-YARA-TOOL_POISONING", ruleIds);
        Assert.Contains("MCP-PROMPT_DEFENSE-PROMPT_INJECTION", ruleIds);
    }

    [Fact]
    public void Wrapped_root_is_read_and_multiple_threats_fan_out()
    {
        // The wrapped {results:[...]} shape, a block with two threat_names → two results.
        var results = Map("wrapped_with_error.json").Runs[0].Results!;
        Assert.Contains(results, r => r.RuleId == "MCP-YARA-CREDENTIAL_HARVESTING");
        Assert.Contains(results, r => r.RuleId == "MCP-YARA-DATA_EXFILTRATION");
    }

    [Fact]
    public void Failed_analyzer_becomes_an_informational_coverage_result()
    {
        var results = Map("wrapped_with_error.json").Runs[0].Results!;
        var coverage = results.Single(r => r.RuleId == "MCP-LLM-COVERAGE");
        Assert.Equal(SarifLevel.None, coverage.Level);
        Assert.Contains("incomplete", coverage.Message.Text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void All_safe_scan_yields_zero_results_but_a_valid_run()
    {
        var run = Map("all_safe.json").Runs[0];
        Assert.Empty(run.Results!);
        Assert.Equal("mcp-scanner", run.Tool.Driver.Name);
    }

    [Fact]
    public void Output_round_trips_through_the_sarif_reader_writer()
    {
        var once = SarifWriter.Serialize(Map("wrapped_with_error.json"));
        var twice = SarifWriter.Serialize(SarifReader.Parse(once));
        Assert.Equal(once, twice);
    }

    [Fact]
    public void Scan_target_is_the_fallback_server_when_result_has_none()
    {
        const string json = """
        [ { "findings": { "yara_analyzer": { "severity": "LOW", "threat_names": ["x"], "total_findings": 1 } },
            "tool_name": "t", "item_type": "tool" } ]
        """;
        var r = CiscoSarifMapper.ToSarif(json, scanTarget: "stdio://local").Runs[0].Results![0];
        Assert.Equal("stdio://local/t", r.Locations![0].LogicalLocations![0].FullyQualifiedName);
    }

    [Fact]
    public void Invalid_json_throws_invalid_data()
    {
        Assert.Throws<InvalidDataException>(() => CiscoSarifMapper.ToSarif("{ not json"));
    }
}
