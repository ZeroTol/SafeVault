// Services/AuthService.cs
using SafeVault.Data;
using SafeVault.Helpers;
using SafeVault.Models.Contracts;

namespace SafeVault.Services;

public interface IAuthService
{
    Task<bool> RegisterAsync(string username, string email, string password);
    Task<LoginResponse?> LoginAsync(string username, string password);   // NEW shape
}

public class AuthService : IAuthService
{
    private readonly IUserRepository _users;
    private readonly IJwtTokenService _jwt;

    public AuthService(IUserRepository users, IJwtTokenService jwt)
    {
        _users = users;
        _jwt   = jwt;
    }

    public async Task<bool> RegisterAsync(string username, string email, string password)
    {
        if (!ValidationHelpers.IsValidInput(username))     return false;
        if (!ValidationHelpers.IsValidEmail(email))        return false;
        if (!ValidationHelpers.IsValidPassword(password))  return false;
        if (!XssProtection.IsSafeInput(username))          return false;
        if (!XssProtection.IsSafeInput(email))             return false;
        if (await _users.GetByUsernameAsync(username) is not null) return false;

        var hash = PasswordHasher.Hash(password);
        return await _users.CreateUserAsync(username, email, hash, "User") > 0;
    }

    public async Task<LoginResponse?> LoginAsync(string username, string password)
    {
        if (!ValidationHelpers.IsValidInput(username))     return null;
        if (string.IsNullOrEmpty(password))                return null;

        var user = await _users.GetByUsernameAsync(username);
        if (user is null)                                  return null;
        if (!PasswordHasher.Verify(password, user.PasswordHash)) return null;

        var token = _jwt.CreateAccessToken(user);
        return new LoginResponse(token, "Bearer", 15 * 60, user.Role);
    }
}