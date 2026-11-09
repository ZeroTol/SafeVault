using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using SafeVault.Models.Contracts;
using SafeVault.Tests;

[TestFixture]
public class TestAuthentication
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
    public void TearDown() { _client.Dispose(); _factory.Dispose(); }

    [Test]
    public async Task Login_With_Valid_Admin_Credentials_Returns_Jwt()
    {
        var res = await _client.PostAsJsonAsync("/api/account/login",
            new LoginRequest("admin", "ChangeMe!P@ssw0rd2024"));

        Assert.That(res.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var body = await res.Content.ReadFromJsonAsync<LoginResponse>();
        Assert.That(body!.AccessToken, Is.Not.Empty);
        Assert.That(body.Role, Is.EqualTo("Admin"));
        Assert.That(body.TokenType, Is.EqualTo("Bearer"));
    }

    [Test]
    public async Task Login_With_Wrong_Password_Returns_401()
    {
        var res = await _client.PostAsJsonAsync("/api/account/login",
            new LoginRequest("admin", "wrong-password"));
        Assert.That(res.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task Login_With_Unknown_User_Returns_401()
    {
        var res = await _client.PostAsJsonAsync("/api/account/login",
            new LoginRequest("ghost", "whatever"));
        Assert.That(res.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task Me_Without_Token_Returns_401()
    {
        var res = await _client.GetAsync("/api/account/me");
        Assert.That(res.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task Me_With_Token_Returns_Role()
    {
        var login = await _client.PostAsJsonAsync("/api/account/login",
            new LoginRequest("admin", "ChangeMe!P@ssw0rd2024"));
        var body = await login.Content.ReadFromJsonAsync<LoginResponse>();

        var req = new HttpRequestMessage(HttpMethod.Get, "/api/account/me");
        req.Headers.Authorization = new("Bearer", body!.AccessToken);

        var res = await _client.SendAsync(req);
        Assert.That(res.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        StringAssert.Contains("Admin", await res.Content.ReadAsStringAsync());
    }
}