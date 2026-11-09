using Microsoft.Data.SqlClient;
using SafeVault.Models;

namespace SafeVault.Data;

public interface IUserRepository
{
    Task<User?> GetByUsernameAsync(string username);
    Task<int>  CreateUserAsync(string username, string email, string passwordHash, string role = "User");
    Task<bool> SetRoleAsync(string username, string role);
    Task<bool> AnyAdminExistsAsync(); 
}

/// <summary>
/// All SQL uses parameterized commands. No string concatenation.
/// </summary>
public class UserRepository : IUserRepository
{
    private readonly string _connectionString;

    public UserRepository(IConfiguration config)
    {
        _connectionString = config.GetConnectionString("DefaultConnection")
            ?? throw new InvalidOperationException("Missing connection string.");
    }

    public async Task<User?> GetByUsernameAsync(string username)
    {
        const string query = "SELECT UserID, Username, Email, PasswordHash FROM Users WHERE Username = @Username";

        await using var connection = new SqlConnection(_connectionString);
        await using var command = new SqlCommand(query, connection);
        command.Parameters.Add("@Username", System.Data.SqlDbType.NVarChar, 100).Value = username;

        await connection.OpenAsync();
        await using var reader = await command.ExecuteReaderAsync();
        if (!await reader.ReadAsync()) return null;

        return new User
        {
            UserID = reader.GetInt32(0),
            Username = reader.GetString(1),
            Email = reader.GetString(2),
            PasswordHash = reader.GetString(3)
        };
    }

    public async Task<int> CreateUserAsync(string username, string email, string passwordHash, string role = "User")
    {
        const string sql = @"
        INSERT INTO Users (Username, Email, PasswordHash, Role)
        OUTPUT INSERTED.UserID
        VALUES (@Username, @Email, @PasswordHash, @Role)";

        await using var conn = new SqlConnection(_connectionString);
        await using var cmd  = new SqlCommand(sql, conn);
        cmd.Parameters.Add("@Username", System.Data.SqlDbType.NVarChar, 100).Value = username;
        cmd.Parameters.Add("@Email",    System.Data.SqlDbType.NVarChar, 254).Value = email;
        cmd.Parameters.Add("@PasswordHash", System.Data.SqlDbType.NVarChar, 255).Value = passwordHash;
        cmd.Parameters.Add("@Role",     System.Data.SqlDbType.NVarChar, 20).Value  = role;

        await conn.OpenAsync();
        return (int)(await cmd.ExecuteScalarAsync() ?? 0);
    }
    
    public async Task<bool> SetRoleAsync(string username, string role)
    {
        const string sql = "UPDATE Users SET Role = @Role WHERE Username = @Username";
        await using var conn = new SqlConnection(_connectionString);
        await using var cmd  = new SqlCommand(sql, conn);
        cmd.Parameters.Add("@Role",     System.Data.SqlDbType.NVarChar, 20).Value  = role;
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
}