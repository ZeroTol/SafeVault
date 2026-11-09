using System.Net;
using System.Text.RegularExpressions;

namespace SafeVault.Helpers;

/// <summary>
/// XSS defense-in-depth: reject obviously malicious payloads and
/// HTML-encode on output. Never trust user input (OWASP A03).
/// NOTE: this blocklist is a secondary layer only — the primary defenses are
/// allow-list validation (<see cref="ValidationHelpers"/>) and output encoding.
/// </summary>
public static class XssProtection
{
    private static readonly string[] DangerousPatterns =
    {
        "<script", "</script", "<iframe", "<svg", "<object", "<embed", "<img",
        "<link", "<style", "<meta", "<base", "<form",
        "javascript:", "vbscript:", "data:text/html", "expression("
    };

    // Any inline event handler: onerror=, onload =, onmouseover=, ...
    private static readonly Regex EventHandler = new(
        @"\bon[a-z]+\s*=",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled,
        TimeSpan.FromMilliseconds(100));

    /// <summary>Returns false if input contains known XSS markers.</summary>
    public static bool IsSafeInput(string? input)
    {
        if (string.IsNullOrEmpty(input)) return true;

        // Decode entities (&lt;script&gt;) and strip whitespace/control chars
        // so "java\tscript:" or "&#106;avascript:" can't slip through.
        var decoded    = WebUtility.HtmlDecode(input);
        var normalized = new string(decoded
            .Where(c => !char.IsWhiteSpace(c) && !char.IsControl(c))
            .ToArray()).ToLowerInvariant();

        if (DangerousPatterns.Any(p => normalized.Contains(p))) return false;
        return !EventHandler.IsMatch(decoded);
    }

    /// <summary>HTML-encodes a string for safe output in Razor or HTML.</summary>
    public static string Encode(string? input) =>
        string.IsNullOrEmpty(input) ? string.Empty : WebUtility.HtmlEncode(input);
}
