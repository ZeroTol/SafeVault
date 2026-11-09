using System.Collections.Concurrent;
using SafeVault.Models;

namespace SafeVault.Data;

/// <summary>
/// In-memory IUserRepository
/// </summary>
public class InMemoryUserRepository : IUserRepository
{
    private readonly ConcurrentDictionary<string, User> _users = new(StringComparer.Ordinal);
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
            UserID       = id,
            Username     = username,
            Email        = email,
            PasswordHash = passwordHash,
            Role         = role
        };
        // TryAdd fails atomically if the username already exists.
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
}