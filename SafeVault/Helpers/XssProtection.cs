using System.Net;

namespace SafeVault.Helpers;

/// <summary>
/// XSS defense-in-depth: reject obviously malicious payloads and
/// HTML-encode on output. Never trust user input (OWASP A03).
/// </summary>
public static class XssProtection
{
    private static readonly string[] DangerousPatterns =
    {
        "<script", "</script", "<iframe", "javascript:", "onerror=", "onload="
    };

    /// <summary>Returns false if input contains known XSS markers.</summary>
    public static bool IsSafeInput(string? input)
    {
        if (string.IsNullOrEmpty(input)) return true;
        var lower = input.ToLowerInvariant();
        return !DangerousPatterns.Any(p => lower.Contains(p));
    }

    /// <summary>HTML-encodes a string for safe output in Razor or HTML.</summary>
    public static string Encode(string? input) =>
        string.IsNullOrEmpty(input) ? string.Empty : WebUtility.HtmlEncode(input);
}