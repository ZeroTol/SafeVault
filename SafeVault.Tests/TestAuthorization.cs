using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using SafeVault.Models.Contracts;
using SafeVault.Tests;

[TestFixture]
public class TestAuthorization
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

    private async Task<string> LoginAsync(string username, string password)
    {
        var res  = await _client.PostAsJsonAsync("/api/account/login",
            new LoginRequest(username, password));
        var body = await res.Content.ReadFromJsonAsync<LoginResponse>();
        return body!.AccessToken;
    }

    [Test]
    public async Task AdminDashboard_Without_Token_Returns_401()
    {
        var res = await _client.GetAsync("/api/admin/dashboard");
        Assert.That(res.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task AdminDashboard_With_Admin_Token_Returns_200()
    {
        var token = await LoginAsync("admin", "ChangeMe!P@ssw0rd2024");
        var req = new HttpRequestMessage(HttpMethod.Get, "/api/admin/dashboard");
        req.Headers.Authorization = new("Bearer", token);

        var res = await _client.SendAsync(req);
        Assert.That(res.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task AdminDashboard_With_User_Token_Returns_403()
    {
        await _client.PostAsJsonAsync("/api/account/register",
            new RegisterRequest("alice", "alice@example.com", "ValidP@ssw0rd123!"));

        var token = await LoginAsync("alice", "ValidP@ssw0rd123!");
        var req = new HttpRequestMessage(HttpMethod.Get, "/api/admin/dashboard");
        req.Headers.Authorization = new("Bearer", token);

        var res = await _client.SendAsync(req);
        Assert.That(res.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
    }

    [Test]
    public async Task Admin_Can_Promote_User_To_Admin_And_New_Token_Is_Accepted()
    {
        await _client.PostAsJsonAsync("/api/account/register",
            new RegisterRequest("bob", "bob@example.com", "ValidP@ssw0rd123!"));

        var adminToken = await LoginAsync("admin", "ChangeMe!P@ssw0rd2024");
        var promote = new HttpRequestMessage(HttpMethod.Post, "/api/admin/users/bob/role")
            { Content = JsonContent.Create(new RoleUpdateRequest("Admin")) };
        promote.Headers.Authorization = new("Bearer", adminToken);
        var pRes = await _client.SendAsync(promote);
        Assert.That(pRes.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var bobToken = await LoginAsync("bob", "ValidP@ssw0rd123!");
        var dashReq  = new HttpRequestMessage(HttpMethod.Get, "/api/admin/dashboard");
        dashReq.Headers.Authorization = new("Bearer", bobToken);
        var dRes = await _client.SendAsync(dashReq);
        Assert.That(dRes.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }
}