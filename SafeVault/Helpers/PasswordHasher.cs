namespace SafeVault.Helpers;

/// <summary>
/// Password hashing via BCrypt (adaptive cost).
/// </summary>
public static class PasswordHasher
{
    public static string Hash(string password) =>
        BCrypt.Net.BCrypt.HashPassword(password, workFactor: 12);

    public static bool Verify(string password, string hash) =>
        BCrypt.Net.BCrypt.Verify(password, hash);
}