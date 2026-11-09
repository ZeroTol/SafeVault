using SafeVault.Data;
using SafeVault.Helpers;
using SafeVault.Models.Contracts;

namespace SafeVault.Services;

public interface IAuthService
{
    Task<bool> RegisterAsync(string username, string email, string password);
    Task<LoginResponse?> LoginAsync(string username, string password, string? ipAddress = null);  // Task 3
}

public class AuthService : IAuthService
{
    private const int MaxFailures = 5;
    private static readonly TimeSpan LockoutFor = TimeSpan.FromMinutes(15);

    private readonly IUserRepository _users;
    private readonly IJwtTokenService _jwt;

    public AuthService(IUserRepository users, IJwtTokenService jwt)
    {
        _users = users;
        _jwt   = jwt;
    }

    public async Task<bool> RegisterAsync(string username, string email, string password)
    {
        if (!ValidationHelpers.IsValidInput(username))    return false;
        if (!ValidationHelpers.IsValidEmail(email))       return false;
        if (!ValidationHelpers.IsValidPassword(password)) return false;
        if (!XssProtection.IsSafeInput(username))         return false;
        if (!XssProtection.IsSafeInput(email))            return false;
        if (await _users.GetByUsernameAsync(username) is not null) return false;

        var hash = PasswordHasher.Hash(password);
        return await _users.CreateUserAsync(username, email, hash, "User") > 0;
    }

    public async Task<LoginResponse?> LoginAsync(string username, string password, string? ipAddress = null)
    {
        if (!ValidationHelpers.IsValidInput(username) || string.IsNullOrEmpty(password))
        {
            await _users.RecordLoginAsync(username ?? "", ipAddress, "Invalid");
            return null;
        }

        var user = await _users.GetByUsernameAsync(username);
        if (user is null)
        {
            await _users.RecordLoginAsync(username, ipAddress, "UnknownUser");
            return null;
        }

        if (user.LockoutUntilUtc is { } until && until > DateTime.UtcNow)
        {
            await _users.RecordLoginAsync(username, ipAddress, "LockedOut");
            return null;
        }

        if (!PasswordHasher.Verify(password, user.PasswordHash))
        {
            var failures = user.FailedLoginCount + 1;
            DateTime? lockUntil = failures >= MaxFailures ? DateTime.UtcNow.Add(LockoutFor) : null;

            await _users.UpdateLockoutAsync(username, failures, lockUntil);
            await _users.RecordLoginAsync(username, ipAddress, "BadPassword");
            return null;
        }

        await _users.UpdateLockoutAsync(username, 0, null);
        await _users.RecordLoginAsync(username, ipAddress, "Success");

        var token = _jwt.CreateAccessToken(user);
        return new LoginResponse(token, "Bearer", _jwt.ExpiresInSeconds, user.Role);
    }
}