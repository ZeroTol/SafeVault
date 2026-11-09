using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using NUnit.Framework;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Models.Contracts;

[TestFixture]
public class TestAccountEndpoints
{
    private WebApplicationFactory<Program> _factory = null!;
    private HttpClient _client = null!;

    [SetUp]
    public void Setup()
    {
        _factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.ConfigureServices(services =>
                {
                    services.RemoveAll<IUserRepository>();
                    services.AddSingleton<IUserRepository, FakeUserRepository>();
                });
            });

        _client = _factory.CreateClient();
    }

    [TearDown]
    public void TearDown()
    {
        _client.Dispose();
        _factory.Dispose();
    }

    [Test]
    public async Task Register_Rejects_SqlInjection_Payload()
    {
        var payload = new RegisterRequest(
            "'; DROP TABLE Users; --", "test@example.com", "ValidP@ssw0rd123!");

        var resp = await _client.PostAsJsonAsync("/api/account/register", payload);
        Assert.That(resp.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    [Test]
    public async Task Register_Rejects_Xss_Payload_In_Username()
    {
        var payload = new RegisterRequest(
            "<script>alert(1)</script>", "test@example.com", "ValidP@ssw0rd123!");

        var resp = await _client.PostAsJsonAsync("/api/account/register", payload);
        Assert.That(resp.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    [Test]
    public async Task Register_Rejects_Invalid_Email()
    {
        var payload = new RegisterRequest(
            "validuser", "not-an-email", "ValidP@ssw0rd123!");

        var resp = await _client.PostAsJsonAsync("/api/account/register", payload);
        Assert.That(resp.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    [Test]
    public async Task Login_Rejects_Empty_Username()
    {
        var resp = await _client.PostAsJsonAsync(
            "/api/account/login", new LoginRequest("", "x"));
        Assert.That(resp.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    // ---------- in-memory fake (all 4 interface members) ----------
    private sealed class FakeUserRepository : IUserRepository
    {
        private readonly Dictionary<string, User> _users = new(StringComparer.Ordinal);

        public Task<User?> GetByUsernameAsync(string username) =>
            Task.FromResult(_users.TryGetValue(username, out var u) ? u : null);

        public Task<int> CreateUserAsync(
            string username, string email, string passwordHash, string role = "User")
        {
            var id = _users.Count + 1;
            _users[username] = new User
            {
                UserID       = id,
                Username     = username,
                Email        = email,
                PasswordHash = passwordHash,
                Role         = role
            };
            return Task.FromResult(id);
        }

        public Task<bool> SetRoleAsync(string username, string role)
        {
            if (!_users.TryGetValue(username, out var u)) return Task.FromResult(false);
            u.Role = role;
            return Task.FromResult(true);
        }

        public Task<bool> AnyAdminExistsAsync() =>
            Task.FromResult(_users.Values.Any(u => u.Role == "Admin"));
    }
}