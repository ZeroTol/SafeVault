using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using NUnit.Framework;
using SafeVault.Models.Contracts;
using SafeVault.Tests;

[TestFixture]
public class TestLockout
{
    private WebApplicationFactory<Program> _factory = null!;
    private HttpClient _client = null!;

    [SetUp]
    public void Setup() { _factory = TestFactory.Create(); _client = _factory.CreateClient(); }
    [TearDown] public void TearDown() { _client.Dispose(); _factory.Dispose(); }

    [Test]
    public async Task Lockout_After_Five_Failures_Then_Success_Still_Blocked()
    {
        // 5 wrong passwords
        for (var i = 0; i < 5; i++)
        {
            var bad = await _client.PostAsJsonAsync("/api/account/login",
                new LoginRequest("admin", "wrong"));
            Assert.That(bad.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
        }

        // Correct password now blocked by lockout → same generic 401.
        var good = await _client.PostAsJsonAsync("/api/account/login",
            new LoginRequest("admin", "ChangeMe!P@ssw0rd2024"));
        Assert.That(good.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task Successful_Login_Resets_Counter()
    {
        await _client.PostAsJsonAsync("/api/account/login",
            new LoginRequest("admin", "wrong"));
        await _client.PostAsJsonAsync("/api/account/login",
            new LoginRequest("admin", "ChangeMe!P@ssw0rd2024"));   // success, resets

        // 4 more bad attempts should still leave 1 attempt before lockout.
        for (var i = 0; i < 4; i++)
            await _client.PostAsJsonAsync("/api/account/login",
                new LoginRequest("admin", "wrong"));

        var last = await _client.PostAsJsonAsync("/api/account/login",
            new LoginRequest("admin", "ChangeMe!P@ssw0rd2024"));
        Assert.That(last.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }
}