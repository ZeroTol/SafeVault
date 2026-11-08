using Microsoft.Data.SqlClient;
using SafeVault.Models;
using SafeVault.Helpers;

namespace SafeVault.Data;

public interface IUserRepository
{
    Task<User?> GetByUsernameAsync(string username);
    Task<int> CreateUserAsync(string username, string email, string passwordHash);
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

    public async Task<int> CreateUserAsync(string username, string email, string passwordHash)
    {
        const string query = @"
            INSERT INTO Users (Username, Email, PasswordHash)
            OUTPUT INSERTED.UserID
            VALUES (@Username, @Email, @PasswordHash)";

        await using var connection = new SqlConnection(_connectionString);
        await using var command = new SqlCommand(query, connection);
        command.Parameters.Add("@Username", System.Data.SqlDbType.NVarChar, 100).Value = username;
        command.Parameters.Add("@Email", System.Data.SqlDbType.NVarChar, 254).Value = email;
        command.Parameters.Add("@PasswordHash", System.Data.SqlDbType.NVarChar, 255).Value = passwordHash;

        await connection.OpenAsync();
        return (int)(await command.ExecuteScalarAsync() ?? 0);
    }
}