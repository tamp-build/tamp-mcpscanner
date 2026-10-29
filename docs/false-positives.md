# False positives — read this before you wire anything to a gate

MCP security scanners are **noisy by design**, and `Tamp.McpScanner` does not
hide that. The honest numbers from the public research:

- A 2026 audit of 33 local MCP servers found Cisco's pattern layer produced
  **27 detections, of which 6 were genuine — roughly a 78% false-positive
  rate.** Every one of the eight "prompt injection" flags was triggered by
  ordinary MCP tool dependency instructions, not an attack.
- The underlying risk is nonetheless real: a study of 1,899 open-source MCP
  servers found **5.5% exhibited tool poisoning**, with weak input sanitisation
  and missing authentication common.

So: a genuine problem, detected by noisy detectors. Two consequences shape how
this wrapper is meant to be used.

## 1. This is nightly, non-blocking evidence — not a per-push gate

`McpScanSource` produces SARIF for `tamp-findings` to **triage and trend**, the
same posture as `SecurityScanTrivy`. Do **not** fail a build on its raw output.
A gate that goes red on a ~78%-false-positive signal teaches people to ignore
it, which is worse than having no gate at all.

If you want a gate eventually, gate on a **triaged** view in `tamp-findings`
(findings a human or a meta-analyzer has confirmed), never on the scanner's
unfiltered results.

## 2. Much of the noise is stack-blindness — use a stack pack

A large share of the false positives come from the pattern rules matching
regexes over tool **descriptions** while baking in shell/Python idioms. A .NET
tool whose description legitimately mentions `app.config` or a NuGet restore
step trips rules written with a different stack in mind.

`Tamp.McpScanner` ships **stack-tuned rule packs** for exactly this. Select one
with `Stack = McpStack.DotNet` (or `TypeScript` / `Python`). See
[`stack-rules.md`](stack-rules.md).

## What the wrapper does to keep the noise legible

- **Severity is preserved, not inflated** — `HIGH → error`, `MEDIUM → warning`,
  `LOW/INFO → note`. Nothing is promoted.
- **Incomplete coverage is visible.** An analyzer that failed to run becomes an
  informational `level:none` result (rule id `MCP-<ANALYZER>-COVERAGE`), so a
  partial scan can never be mistaken for a clean one. Silence is evidence.
- **Stable identity for dedup.** Each finding carries a SARIF `logicalLocation`
  (`server/tool`) and mirrors it into `partialFingerprints`, so the same
  finding across nightly runs collapses instead of accumulating.
- **No synthesised file paths.** These findings are about an advertised *tool*,
  not a file, so the wrapper never invents a `physicalLocation` to make the
  output look like static analysis.
