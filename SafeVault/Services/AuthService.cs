using SafeVault.Data;
using SafeVault.Helpers;

namespace SafeVault.Services;

public interface IAuthService
{
    Task<bool> RegisterAsync(string username, string email, string password);
    Task<bool> LoginAsync(string username, string password);
}

/// <summary>
/// Authentication service. Validates all inputs, hashes passwords,
/// and uses parameterized repository queries.
/// </summary>
public class AuthService : IAuthService
{
    private readonly IUserRepository _users;

    public AuthService(IUserRepository users) => _users = users;

    public async Task<bool> RegisterAsync(string username, string email, string password)
    {
        if (!ValidationHelpers.IsValidInput(username)) return false;
        if (!ValidationHelpers.IsValidEmail(email)) return false;
        if (!ValidationHelpers.IsValidPassword(password)) return false;
        if (!XssProtection.IsSafeInput(username) || !XssProtection.IsSafeInput(email)) return false;

        if (await _users.GetByUsernameAsync(username) is not null) return false;

        var hash = PasswordHasher.Hash(password);
        var id = await _users.CreateUserAsync(username, email, hash);
        return id > 0;
    }

    public async Task<bool> LoginAsync(string username, string password)
    {
        if (!ValidationHelpers.IsValidInput(username)) return false;
        if (string.IsNullOrEmpty(password)) return false;

        var user = await _users.GetByUsernameAsync(username);
        return user is not null && PasswordHasher.Verify(password, user.PasswordHash);
    }
}