# .NET rule pack

An overlay on the `common` base: when the `dotnet` pack is materialised, the
full base rule set is written first and then the files here replace their
same-named base rules. So this folder carries **only the rules that needed
.NET-specific tuning**, not the whole set — the untuned base rules still apply.

See [`../../../docs/stack-rules.md`](../../../../docs/stack-rules.md) for why
stack tuning exists and how to add to it.

## Tuned rules

| Rule | Change | Why |
|---|---|---|
| `credential_harvesting.yara` | Added `$dotnet_config_idioms` negative guard to the file-based branch. | The base matches the `.config` extension + an action word, so "reads `app.config` / `web.config`" or "loads `appsettings.json` via `IConfiguration`" — ordinary .NET configuration access — was flagged as credential harvesting. The guard suppresses only genuine .NET config phrasing (`app.config`, `web.config`, `appsettings[.*].json`, `IConfiguration`, `ConfigurationManager`, `ConfigurationBuilder`, `IOptions*`, `GetConnectionString`, `AddJsonFile`, `AddUserSecrets`, `builder.Configuration`). Detection is otherwise byte-identical to the base. |

## Candidates not yet tuned (contributions welcome)

These base rules are the next most likely to misfire on .NET tool descriptions.
They are **not** overlaid here yet — using the `dotnet` pack today runs the
untuned base versions of them, which is correct but may be noisy:

- `command_injection.yara` — `$windows_cmds` matches `powershell`, `cmd /c`,
  `reg `, `wmic`. A tool that legitimately *wraps* those is suspicious even in
  .NET, so tune conservatively (or not at all).
- `code_execution.yara` — reflection / dynamic-load phrasing (`Assembly.Load`,
  `Activator.CreateInstance`) can read as code execution.
- `tool_poisoning.yara` — "also/additionally …" phrasing in a description that
  legitimately documents multiple behaviours.

Tune a rule by copying the base file here and adding a narrow negative
condition — keep the rule name and the detection strings identical so the
overlay is a true drop-in replacement, and add a row above. Validate against
your own server's real descriptions before trusting a change.
