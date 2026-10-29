# Tamp.McpScanner

Tamp wrapper for Cisco's [`mcp-scanner`](https://github.com/cisco-ai-defense/mcp-scanner).
Scans MCP (Model Context Protocol) servers for tool-poisoning, prompt-injection,
credential-harvesting and related threats — and **normalises the scanner's JSON
into SARIF 2.1.0** so MCP findings flow through the Tamp security chain
(`Tamp.Sarif` merge/dedup → `SecurityPush` → `tamp-findings`) alongside OpenGrep,
Trivy and the Roslyn leg.

## Why this exists

Tamp's security chain is SARIF-centric, but **no MCP security scanner emits
SARIF** — Cisco's emits JSON, Snyk's emits JSON. So MCP findings have had
nowhere to go. The contribution here is the normalisation: a `mcp-scanner`
run becomes a SARIF `IFindingSource` like any other scanner in the chain.

Tamp itself ships an MCP server (`tamp mcp`), so there is an in-tree dogfood
target.

## Install

```sh
dotnet add package Tamp.McpScanner
```

You also need the Cisco CLI on the machine that runs the scan:

```sh
uv tool install --python 3.13 cisco-ai-mcp-scanner   # provides `mcp-scanner`
```

## Usage

`McpScanner` returns an `IFindingSource`; call `ScanAsync()` to run the scan and
get a normalised `SarifLog`.

```csharp
using Tamp.McpScanner;
using Tamp.Sarif;

// A running server over HTTP/SSE.
var source = McpScanner.ScanRemote(s =>
{
    s.ServerUrl = "https://localhost:5000/mcp";
    s.BearerToken = new Secret("mcp", token);   // typed → redacted in logs/dry-run
    s.Stack = McpStack.DotNet;                   // .NET-tuned rule pack (see below)
});

SarifLog sarif = await source.ScanAsync();
SarifWriter.WriteToFile(sarif, artifacts / "security" / "mcp.sarif");
```

Three scan modes:

| Method | mcp-scanner | For |
|---|---|---|
| `ScanRemote` | `remote --server-url …` | a running server (HTTP/SSE) |
| `ScanStatic` | `static --tools …` | a saved `tools/list` manifest — air-gapped, no live server (and the fixture path for tests) |
| `ScanConfig` | `--config-path …` | the servers declared in an MCP client config (covers stdio servers) |

## Analyzers

Offline by default — **no key, no egress**: `yara`, `readiness`, `prompt_defense`.
That keeps the air-gapped posture `tamp-observer` / `tamp-findings` are built
around. Everything else is opt-in:

```csharp
s.Analyzers.Add(McpAnalyzer.Llm);
s.LlmEndpointUrl = "http://localhost:11434";   // point the LLM analyzer at local Ollama → stays on-prem
```

- `McpAnalyzer.Llm` — behavioural/source analysis via an LLM; on-prem if pointed
  at a local endpoint.
- `McpAnalyzer.Api` — Cisco AI Defense; needs a vendor key and **egresses**.

Enabling any analyzer that reaches a model or vendor service marks the command
`SideEffectful`; the offline default stays `Safe`.

## False positives — important

MCP pattern detectors are noisy (a 2026 audit measured **~78% false positives**
on the pattern layer). This wrapper is built to produce **nightly, non-blocking
evidence** for `tamp-findings` to triage and trend — **not** a per-push gate.
Do not fail a build on its raw output. See [`docs/false-positives.md`](docs/false-positives.md).

## Stack-aware rule packs

A large share of that noise is stack-blindness: Cisco's rules match tool
*descriptions* with shell/Python idioms baked in, so idiomatic .NET or
TypeScript phrasing misfires. Select a tuned pack:

```csharp
s.Stack = McpStack.DotNet;   // or TypeScript, Python
```

`Common` is the faithful base; `DotNet` overlays .NET-config tuning on top.
See [`docs/stack-rules.md`](docs/stack-rules.md). Rule content is Cisco's
(Apache-2.0); per-stack tuning is the Tamp Project's — see [`NOTICE`](NOTICE).

## How findings are shaped

MCP findings are about an advertised **tool**, not a file, so each SARIF result
carries a `logicalLocation` (`server/tool`), never a synthesised path, and
mirrors it into `partialFingerprints` for stable cross-run dedup. A failed
analyzer becomes an informational `level:none` coverage result so a partial
scan is never mistaken for a clean one.

> Requires `Tamp.Sarif` ≥ 1.17.5 (the SARIF `logicalLocations` support this
> normalisation depends on).

## License

MIT for the Tamp code (see [`LICENSE`](LICENSE)). The bundled YARA rule packs
are derived from Cisco's mcp-scanner and remain under Apache-2.0 (see
[`NOTICE`](NOTICE)).
