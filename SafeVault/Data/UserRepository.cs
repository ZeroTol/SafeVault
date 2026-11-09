using Microsoft.Data.SqlClient;
using SafeVault.Models;

namespace SafeVault.Data;

public class UserRepository : IUserRepository
{
    private readonly string _connectionString;

    public UserRepository(IConfiguration config)
    {
        _connectionString = config.GetConnectionString("DefaultConnection")
            ?? throw new InvalidOperationException("Missing connection string 'DefaultConnection'.");
    }

    // ----- Task 1 / Task 2 (now reads lockout columns) -----

    public async Task<User?> GetByUsernameAsync(string username)
    {
        const string sql = @"
            SELECT UserID, Username, Email, PasswordHash, Role, FailedLoginCount, LockoutUntilUtc
            FROM Users WHERE Username = @Username";

        await using var conn = new SqlConnection(_connectionString);
        await using var cmd  = new SqlCommand(sql, conn);
        cmd.Parameters.Add("@Username", System.Data.SqlDbType.NVarChar, 100).Value = username;

        await conn.OpenAsync();
        await using var r = await cmd.ExecuteReaderAsync();
        if (!await r.ReadAsync()) return null;

        return new User
        {
            UserID           = r.GetInt32(0),
            Username         = r.GetString(1),
            Email            = r.GetString(2),
            PasswordHash     = r.GetString(3),
            Role             = r.GetString(4),
            FailedLoginCount = r.GetInt32(5),
            LockoutUntilUtc  = r.IsDBNull(6) ? null : r.GetDateTime(6)
        };
    }

    public async Task<int> CreateUserAsync(
        string username, string email, string passwordHash, string role = "User")
    {
        const string sql = @"
            INSERT INTO Users (Username, Email, PasswordHash, Role)
            OUTPUT INSERTED.UserID
            VALUES (@Username, @Email, @PasswordHash, @Role)";

        await using var conn = new SqlConnection(_connectionString);
        await using var cmd  = new SqlCommand(sql, conn);
        cmd.Parameters.Add("@Username",     System.Data.SqlDbType.NVarChar, 100).Value = username;
        cmd.Parameters.Add("@Email",        System.Data.SqlDbType.NVarChar, 254).Value = email;
        cmd.Parameters.Add("@PasswordHash", System.Data.SqlDbType.NVarChar, 255).Value = passwordHash;
        cmd.Parameters.Add("@Role",         System.Data.SqlDbType.NVarChar, 20 ).Value = role;

        try
        {
            await conn.OpenAsync();
            return (int)(await cmd.ExecuteScalarAsync() ?? 0);
        }
        catch (SqlException ex) when (ex.Number is 2627 or 2601)
        {
            return 0;
        }
    }

    public async Task<bool> SetRoleAsync(string username, string role)
    {
        const string sql = "UPDATE Users SET Role = @Role WHERE Username = @Username";
        await using var conn = new SqlConnection(_connectionString);
        await using var cmd  = new SqlCommand(sql, conn);
        cmd.Parameters.Add("@Role",     System.Data.SqlDbType.NVarChar, 20 ).Value = role;
        cmd.Parameters.Add("@Username", System.Data.SqlDbType.NVarChar, 100).Value = username;
        await conn.OpenAsync();
        return await cmd.ExecuteNonQueryAsync() == 1;
    }

    public async Task<bool> AnyAdminExistsAsync()
    {
        const string sql = "SELECT COUNT(1) FROM Users WHERE Role = 'Admin'";
        await using var conn = new SqlConnection(_connectionString);
        await using var cmd  = new SqlCommand(sql, conn);
        await conn.OpenAsync();
        return (int)(await cmd.ExecuteScalarAsync() ?? 0) > 0;
    }

    // ----- Task 3 -----

    public async Task RecordLoginAsync(string username, string? ipAddress, string outcome)
    {
        const string sql = @"
            INSERT INTO LoginAudit (Username, IpAddress, Outcome)
            VALUES (@Username, @Ip, @Outcome)";

        await using var conn = new SqlConnection(_connectionString);
        await using var cmd  = new SqlCommand(sql, conn);
        cmd.Parameters.Add("@Username", System.Data.SqlDbType.NVarChar, 100).Value = username;
        cmd.Parameters.Add("@Ip",       System.Data.SqlDbType.NVarChar, 64 ).Value = (object?)ipAddress ?? DBNull.Value;
        cmd.Parameters.Add("@Outcome",  System.Data.SqlDbType.NVarChar, 20 ).Value = outcome;
        await conn.OpenAsync();
        await cmd.ExecuteNonQueryAsync();
    }

    public async Task UpdateLockoutAsync(string username, int failedCount, DateTime? lockoutUntilUtc)
    {
        const string sql = @"
            UPDATE Users
            SET FailedLoginCount = @Count, LockoutUntilUtc = @Until
            WHERE Username = @Username";

        await using var conn = new SqlConnection(_connectionString);
        await using var cmd  = new SqlCommand(sql, conn);
        cmd.Parameters.Add("@Count",    System.Data.SqlDbType.Int          ).Value = failedCount;
        cmd.Parameters.Add("@Until",    System.Data.SqlDbType.DateTime2    ).Value = (object?)lockoutUntilUtc ?? DBNull.Value;
        cmd.Parameters.Add("@Username", System.Data.SqlDbType.NVarChar, 100).Value = username;
        await conn.OpenAsync();
        await cmd.ExecuteNonQueryAsync();
    }

    public async Task<IReadOnlyList<LoginAuditRow>> GetRecentLoginsAsync(int take)
    {
        const string sql = @"
            SELECT TOP (@Take) Username, IpAddress, Outcome, CreatedUtc
            FROM LoginAudit
            ORDER BY CreatedUtc DESC";

        var rows = new List<LoginAuditRow>();
        await using var conn = new SqlConnection(_connectionString);
        await using var cmd  = new SqlCommand(sql, conn);
        cmd.Parameters.Add("@Take", System.Data.SqlDbType.Int).Value = Math.Clamp(take, 1, 500);

        await conn.OpenAsync();
        await using var r = await cmd.ExecuteReaderAsync();
        while (await r.ReadAsync())
        {
            rows.Add(new LoginAuditRow(
                r.GetString(0),
                r.IsDBNull(1) ? null : r.GetString(1),
                r.GetString(2),
                r.GetDateTime(3)));
        }
        return rows;
    }
}