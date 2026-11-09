using SafeVault.Models;

namespace SafeVault.Data;

public interface IUserRepository
{
    Task<User?> GetByUsernameAsync(string username);
    Task<int>   CreateUserAsync(string username, string email, string passwordHash, string role = "User");
    Task<bool>  SetRoleAsync(string username, string role);
    Task<bool>  AnyAdminExistsAsync();

    Task RecordLoginAsync(string username, string? ipAddress, string outcome);
    Task UpdateLockoutAsync(string username, int failedCount, DateTime? lockoutUntilUtc);
    Task<IReadOnlyList<LoginAuditRow>> GetRecentLoginsAsync(int take);
}