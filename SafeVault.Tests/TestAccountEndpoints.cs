using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using SafeVault.Models.Contracts;
using SafeVault.Tests;

[TestFixture]
public class TestAccountEndpoints
{
    private WebApplicationFactory<Program> _factory = null!;
    private HttpClient _client = null!;

    [SetUp]
    public void Setup()
    {
        _factory = TestFactory.Create();
        _client  = _factory.CreateClient();
    }

    [TearDown]
    public void TearDown()
    {
        _client.Dispose();
        _factory.Dispose();
    }

    // SQLi / XSS through the register username are covered in TestSecurityAttacks.

    [Test]
    public async Task Register_Rejects_Invalid_Email()
    {
        var payload = new RegisterRequest(
            "validuser", "not-an-email", "ValidP@ssw0rd123!");

        var resp = await _client.PostAsJsonAsync("/api/account/register", payload);
        Assert.That(resp.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    [Test]
    public async Task Register_Accepts_Valid_User()
    {
        var payload = new RegisterRequest(
            "carol", "carol@example.com", "ValidP@ssw0rd123!");

        var resp = await _client.PostAsJsonAsync("/api/account/register", payload);
        Assert.That(resp.StatusCode, Is.EqualTo(HttpStatusCode.Created));
    }

    [Test]
    public async Task Login_Rejects_Empty_Username()
    {
        var resp = await _client.PostAsJsonAsync(
            "/api/account/login", new LoginRequest("", "x"));
        Assert.That(resp.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    // Classic auth-bypass payloads must never yield a token.
    [TestCase("' OR '1'='1")]
    [TestCase("admin'--")]
    [TestCase("admin' OR 1=1--")]
    [TestCase("'; DROP TABLE Users; --")]
    [TestCase("admin\"; --")]
    public async Task Login_Rejects_SqlInjection_In_Username(string payload)
    {
        var resp = await _client.PostAsJsonAsync(
            "/api/account/login", new LoginRequest(payload, "anything"));

        Assert.That(resp.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        Assert.That(await resp.Content.ReadAsStringAsync(), Does.Not.Contain("accessToken"));
    }

    [TestCase("' OR '1'='1")]
    [TestCase("' OR 1=1--")]
    [TestCase("ChangeMe!P@ssw0rd2024' OR '1'='1")]
    public async Task Login_SqlInjection_In_Password_Is_Unauthorized(string payload)
    {
        var resp = await _client.PostAsJsonAsync(
            "/api/account/login", new LoginRequest("admin", payload));
        Assert.That(resp.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task SqlInjection_Attempt_Does_Not_Damage_Data()
    {
        await _client.PostAsJsonAsync("/api/account/login",
            new LoginRequest("'; DROP TABLE Users; --", "x"));

        // Admin account must still exist and work afterwards.
        var resp = await _client.PostAsJsonAsync("/api/account/login",
            new LoginRequest("admin", "ChangeMe!P@ssw0rd2024"));
        Assert.That(resp.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [TestCase("<script>alert(1)</script>")]
    [TestCase("<img src=x onerror=alert(1)>")]
    [TestCase("<svg/onload=alert(1)>")]
    public async Task Login_Rejects_Xss_In_Username_Without_Reflecting_It(string payload)
    {
        var resp = await _client.PostAsJsonAsync(
            "/api/account/login", new LoginRequest(payload, "anything"));

        Assert.That(resp.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        Assert.That(await resp.Content.ReadAsStringAsync(), Does.Not.Contain(payload));
    }

    [Test]
    public async Task Oversized_Body_Is_Rejected()
    {
        var huge = new string('a', 128 * 1024);
        var payload = new RegisterRequest(huge, "a@b.co", "ValidP@ssw0rd123!");

        var res = await _client.PostAsJsonAsync("/api/account/register", payload);
        Assert.That((int)res.StatusCode, Is.GreaterThanOrEqualTo(400));  // 400/413
    }
}
