# Stack-aware rule packs

## The problem

Cisco's YARA rules match regexes over tool **descriptions** (and names /
parameters), and they bake in shell- and Python-flavoured idioms. The scanner
does not know what stack the server is written in, so legitimate, idiomatic
phrasing for *another* stack reads as an attack:

- A .NET tool that says it "reads `app.config`" or "loads `appsettings.json`
  via `IConfiguration`" hits `credential_harvesting` (the `.config` extension +
  an action word).
- Connection-string and configuration APIs look like credential access.

This is the stack-blindness behind a large share of the false positives
documented in [`false-positives.md`](false-positives.md).

## The mechanism

mcp-scanner takes a `--rules-path <dir>` that **replaces** its built-in YARA
rules with the directory you give it. `Tamp.McpScanner` ships tuned rule packs
as embedded resources and materialises the right one to a temp directory at
scan time, then points `--rules-path` at it. Because the flag *replaces*, each
pack is a **complete** rule set:

```
common/      ← the full base: faithful copies of Cisco's 10 rules (Apache-2.0)
dotnet/      ← overlay: only the rules that needed .NET tuning
typescript/  ← (planned)
python/      ← (planned)
```

`StackRules.Materialize(stack, dir)` writes `common/` first, then overlays the
selected stack's files on top (same filename wins). The result is the full base
with the stack's rules swapped in — so tuning a rule never loses the other
nine.

## Using it

```csharp
using Tamp.McpScanner;

var source = McpScanner.ScanRemote(s =>
{
    s.ServerUrl = "https://localhost:5000/mcp";
    s.Stack = McpStack.DotNet;          // use the .NET-tuned pack
});

var sarif = await source.ScanAsync();
```

Or bring your own complete rule directory and skip the packs entirely:

```csharp
s.CustomRulesPath = "/path/to/my/rules";   // replaces the built-in rules wholesale
```

`CustomRulesPath` wins over `Stack` if both are set. A `CustomRulesPath` you
pass is yours — the wrapper never deletes it; only the temp dir it materialises
for a `Stack` is cleaned up after the scan.

## Adding or extending a pack

1. Copy the base rule from `rules/common/<rule>.yara` into the stack folder.
2. Add a narrow **negative** condition for the idioms that misfire (a new
   `$stack_idioms` string, `and not $stack_idioms` on the offending branch).
   Keep the rule **name** and the detection strings identical — the overlay has
   to be a true drop-in replacement of that rule.
3. Note the change in the file header and its `author` metadata (see the
   `dotnet/credential_harvesting.yara` worked example), and update the stack
   folder's `README.md` table.
4. **Validate against your own server's real tool descriptions.** A tuning that
   silences a real finding is worse than the false positive it removed.

YARA cannot "subtract" a match, so tuning always means editing the rule's
condition, never adding a standalone allowlist file. That is why packs are
complete sets rather than additive fragments.

## Attribution

The rule content is Cisco's (Apache-2.0); the per-stack negative conditions are
the Tamp Project's. See [`NOTICE`](../NOTICE).
