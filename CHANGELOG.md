# Changelog

All notable changes to Tamp.McpScanner are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release. Wraps Cisco `mcp-scanner` and normalises its JSON into SARIF
  2.1.0 via an `IFindingSource` (`McpScanSource`).
- `ScanRemote` / `ScanStatic` / `ScanConfig` scan modes.
- Offline analyzers (`yara`, `readiness`, `prompt_defense`) by default; `Llm`
  and `Api` opt-in.
- Stack-aware YARA rule packs (`common` base + `dotnet` overlay) via
  `McpStack` / `--rules-path`, with a bring-your-own `CustomRulesPath`.
- Findings carry SARIF `logicalLocations` + `partialFingerprints` (no
  synthesised file paths); failed analyzers surface as informational coverage
  results. Requires Tamp.Sarif >= 1.17.5.
