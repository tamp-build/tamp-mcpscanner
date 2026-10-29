using System.Reflection;

namespace Tamp.McpScanner;

/// <summary>
/// Materialises the embedded, stack-tuned YARA rule packs to a directory on
/// disk so they can be passed to mcp-scanner's <c>--rules-path</c> (which wants
/// a directory and REPLACES the built-in rules — so each pack is a complete
/// set). A stack pack is the <see cref="McpStack.Common"/> base with the
/// over-firing rules replaced by stack-tuned copies: materialisation writes the
/// base first, then overlays the stack's files on top (same filename wins).
/// </summary>
/// <remarks>
/// Packs live in the assembly as embedded resources under
/// <c>Tamp.McpScanner.rules.&lt;pack&gt;.*</c>, so this behaves identically from a
/// project reference or the published nupkg, with no content-file packaging to
/// get wrong. See docs/stack-rules.md.
/// </remarks>
public static class StackRules
{
    private static readonly Assembly Owner = typeof(StackRules).Assembly;
    private const string ResourceRoot = "Tamp.McpScanner.rules.";

    /// <summary>
    /// Write the rule pack for <paramref name="stack"/> into <paramref name="destinationDir"/>
    /// (created if needed) and return that path. The common base is written
    /// first; a non-common stack then overlays its tuned files on top.
    /// </summary>
    /// <exception cref="InvalidOperationException">No rule files were found for the requested pack(s).</exception>
    public static string Materialize(McpStack stack, string destinationDir)
    {
        if (destinationDir is null) throw new ArgumentNullException(nameof(destinationDir));
        Directory.CreateDirectory(destinationDir);

        var written = ExtractPack(McpStack.Common, destinationDir);
        if (stack != McpStack.Common)
            written += ExtractPack(stack, destinationDir);

        if (written == 0)
            throw new InvalidOperationException(
                $"No embedded rule files found for stack '{stack}'. Expected resources under '{ResourceRoot}{stack.PackName()}.'. " +
                "The rule packs may not have been authored/embedded for this build.");

        return destinationDir;
    }

    /// <summary>
    /// Materialise the pack into a fresh temp directory and return its path. The
    /// caller owns the directory's lifetime (delete when the scan is done).
    /// </summary>
    public static string MaterializeToTemp(McpStack stack)
    {
        var dir = Path.Combine(Path.GetTempPath(), "tamp-mcp-rules-" + Guid.NewGuid().ToString("N"));
        return Materialize(stack, dir);
    }

    /// <summary>The filenames embedded for a given pack (no directory component). Empty when none.</summary>
    public static IReadOnlyList<string> PackFiles(McpStack stack)
    {
        var prefix = ResourceRoot + stack.PackName() + ".";
        return Owner.GetManifestResourceNames()
            .Where(n => n.StartsWith(prefix, StringComparison.Ordinal))
            .Select(n => n[prefix.Length..])
            .ToList();
    }

    private static int ExtractPack(McpStack stack, string destinationDir)
    {
        var prefix = ResourceRoot + stack.PackName() + ".";
        var count = 0;
        foreach (var resource in Owner.GetManifestResourceNames())
        {
            if (!resource.StartsWith(prefix, StringComparison.Ordinal)) continue;
            var fileName = resource[prefix.Length..];
            using var stream = Owner.GetManifestResourceStream(resource);
            if (stream is null) continue;
            using var file = File.Create(Path.Combine(destinationDir, fileName));
            stream.CopyTo(file);
            count++;
        }
        return count;
    }
}
