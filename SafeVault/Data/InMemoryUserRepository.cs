using System.Collections.Concurrent;
using SafeVault.Models;

namespace SafeVault.Data;

public class InMemoryUserRepository : IUserRepository
{
    private readonly ConcurrentDictionary<string, User> _users = new(StringComparer.Ordinal);
    private readonly ConcurrentQueue<LoginAuditRow> _audit = new();
    private int _nextId;

    public Task<User?> GetByUsernameAsync(string username)
    {
        _users.TryGetValue(username, out var user);
        return Task.FromResult(user);
    }

    public Task<int> CreateUserAsync(
        string username, string email, string passwordHash, string role = "User")
    {
        var id = Interlocked.Increment(ref _nextId);
        var user = new User
        {
            UserID           = id,
            Username         = username,
            Email            = email,
            PasswordHash     = passwordHash,
            Role             = role,
            FailedLoginCount = 0,
            LockoutUntilUtc  = null
        };
        return Task.FromResult(_users.TryAdd(username, user) ? id : 0);
    }

    public Task<bool> SetRoleAsync(string username, string role)
    {
        if (!_users.TryGetValue(username, out var user)) return Task.FromResult(false);
        user.Role = role;
        return Task.FromResult(true);
    }

    public Task<bool> AnyAdminExistsAsync() =>
        Task.FromResult(_users.Values.Any(u => u.Role == "Admin"));

    // ----- Task 3 -----

    public Task RecordLoginAsync(string username, string? ipAddress, string outcome)
    {
        _audit.Enqueue(new LoginAuditRow(username, ipAddress, outcome, DateTime.UtcNow));
        return Task.CompletedTask;
    }

    public Task UpdateLockoutAsync(string username, int failedCount, DateTime? lockoutUntilUtc)
    {
        if (_users.TryGetValue(username, out var u))
        {
            u.FailedLoginCount = failedCount;
            u.LockoutUntilUtc  = lockoutUntilUtc;
        }
        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<LoginAuditRow>> GetRecentLoginsAsync(int take)
    {
        IReadOnlyList<LoginAuditRow> rows = _audit
            .Reverse()
            .Take(Math.Clamp(take, 1, 500))
            .ToList();
        return Task.FromResult(rows);
    }
}