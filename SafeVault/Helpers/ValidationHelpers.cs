namespace SafeVault.Helpers;

/// <summary>
/// Centralized input validation. Rejects null/empty, enforces length
/// limits, and restricts characters to a safe allow-list (OWASP A03).
/// </summary>
public static class ValidationHelpers
{
    public const int MaxUsernameLength = 50;
    public const int MaxEmailLength = 254;

    /// <summary>Validates general text: letters, digits, and allowed special chars only.</summary>
    public static bool IsValidInput(string? input, string allowedSpecialCharacters = "")
    {
        if (string.IsNullOrWhiteSpace(input)) return false;
        if (input.Length > MaxUsernameLength) return false;

        var allowed = allowedSpecialCharacters.ToHashSet();
        return input.All(c => char.IsLetterOrDigit(c) || allowed.Contains(c));
    }

    /// <summary>Validates an email using a conservative regex and length check.</summary>
    public static bool IsValidEmail(string? email)
    {
        if (string.IsNullOrWhiteSpace(email)) return false;
        if (email.Length > MaxEmailLength) return false;

        // Conservative pattern — not full RFC 5322, but safe for app input.
        return System.Text.RegularExpressions.Regex.IsMatch(
            email,
            @"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
            System.Text.RegularExpressions.RegexOptions.None,
            TimeSpan.FromMilliseconds(100));
    }

    /// <summary>Validates a password meets minimum strength requirements.</summary>
    public static bool IsValidPassword(string? password)
    {
        if (string.IsNullOrEmpty(password)) return false;
        if (password.Length < 12 || password.Length > 128) return false;
        return password.Any(char.IsUpper)
               && password.Any(char.IsLower)
               && password.Any(char.IsDigit)
               && password.Any(c => "!@#$%^&*?".Contains(c));
    }
}