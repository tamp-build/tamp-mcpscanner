# Changelog

All notable changes to `Tamp.McpScanner` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — 2026-11-04

Requires Tamp.Core and Tamp.Sarif 1.17.5 or later (the `logicalLocations` release, [tamp-build/tamp#114](https://github.com/tamp-build/tamp/issues/114)). Tested against 1.17.5 and 1.18.0.

### Added

- Initial release: a Tamp wrapper for Cisco's [`mcp-scanner`](https://github.com/cisco-ai-defense/mcp-scanner), which scans MCP servers for tool poisoning, prompt injection, credential harvesting and related threats. The `mcp-scanner` CLI has to be on the machine that runs the scan; nothing is downloaded.
  - `McpScanner.ScanRemote` (a running server over HTTP/SSE: `ServerUrl`, `BearerToken`, repeatable `Headers`), `ScanStatic` (saved `tools/list`, prompts and resources manifests; air-gapped, no live server) and `ScanConfig` (the servers in an MCP client config file, which covers stdio servers).
  - Each returns an `McpScanSource`, an `IFindingSource`, so `ScanAsync()` slots into the Tamp.Sarif security chain next to the OpenGrep and Trivy sources.
  - Offline analyzers by default: `yara`, `readiness`, `prompt_defense`. No key and no egress. `McpAnalyzer.Llm` (with `LlmEndpointUrl`, e.g. a local Ollama, and `LlmApiKey`) and `McpAnalyzer.Api` (Cisco AI Defense, `ApiKey`) are opt-in, and enabling any of them marks the command `SideEffectful`. The offline default is `Safe`.
  - Bearer tokens and API keys are typed `Secret`s, registered for redaction.
  - `SeverityFilter`, `Executable`, `WorkingDirectory` and environment variables pass through.
  - A non-zero scanner exit with parseable JSON counts as findings, not a failure, because Cisco doesn't document its exit codes. The scan fails only when the scanner produced no parseable output, and the error includes its stderr.
- `CiscoSarifMapper`: a pure JSON→SARIF 2.1.0 normaliser. It accepts a bare array of results or an object that wraps them, and emits one result per item, analyzer and threat, with one rule per analyzer and threat (`MCP-<ANALYZER>-<THREAT>`).
  - Findings are about an advertised tool, prompt or resource, not a file, so each result carries a SARIF `logicalLocation` (`server/item`) and never a synthesised file path. The same identity goes into `partialFingerprints` so dedup across runs stays stable.
  - An analyzer that failed (`error` / `partial`) becomes an informational `level: none` coverage result, so a partial scan never reads as clean.
- Stack-aware YARA rule packs, embedded in the assembly and written to a temp directory for `--rules-path` at scan time, which works the same from a project reference or the nupkg. The temp directory is deleted afterwards.
  - `common`: faithful copies of Cisco's 10 base rules (Apache-2.0, see `NOTICE`).
  - `dotnet`: overlays a .NET-tuned `credential_harvesting` that stops ordinary configuration access (`app.config`, `appsettings.json`, `IConfiguration`, `GetConnectionString`, …) from being flagged. Detection is otherwise unchanged.
  - Select a pack with `Stack = McpStack.Common` / `McpStack.DotNet`, or bring a complete rule directory with `CustomRulesPath`, which wins over `Stack` and is never deleted. TypeScript and Python packs are planned.
  - `StackRules.Materialize`, `MaterializeToTemp` and `PackFiles` are public, for inspecting or reusing a pack.
- `IMcpScannerProcess`: the seam between the source and the scanner process. The default runs it through Tamp's `ProcessRunner`; tests substitute canned scanner JSON.
- [`docs/false-positives.md`](docs/false-positives.md) and [`docs/stack-rules.md`](docs/stack-rules.md). MCP pattern detectors are noisy (about 78% false positives on the pattern layer in a 2026 audit), so this is meant for nightly, non-blocking evidence, not a per-push gate.
- Multi-targets `net8.0;net9.0;net10.0`.
- Package licence is `MIT AND Apache-2.0`: the Tamp code is MIT, and the embedded rule packs stay under Apache-2.0. `NOTICE` ships in the package.
