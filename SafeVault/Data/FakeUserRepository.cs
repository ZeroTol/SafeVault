using SafeVault.Models;

namespace SafeVault.Data;

public sealed class FakeUserRepository : IUserRepository
{
    private readonly Dictionary<string, User> _users = new();

    public Task<User?> GetByUsernameAsync(string username) =>
        Task.FromResult(_users.TryGetValue(username, out var u) ? u : null);

    public Task<int> CreateUserAsync(string username, string email, string passwordHash)
    {
        _users[username] = new User
        {
            UserID = _users.Count + 1,
            Username = username,
            Email = email,
            PasswordHash = passwordHash
        };
        return Task.FromResult(_users[username].UserID);
    }
}