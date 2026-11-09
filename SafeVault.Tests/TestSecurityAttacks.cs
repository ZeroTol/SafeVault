using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using SafeVault.Endpoints;
using SafeVault.Models.Contracts;
using SafeVault.Tests;

[TestFixture]
public class TestSecurityAttacks
{
    private WebApplicationFactory<Program> _factory = null!;
    private HttpClient _client = null!;

    [SetUp]
    public void Setup() { _factory = TestFactory.Create(); _client = _factory.CreateClient(); }

    [TearDown]
    public void TearDown() { _client.Dispose(); _factory.Dispose(); }

    // ---------- SQL injection ----------

    [TestCase("' OR '1'='1")]
    [TestCase("'; DROP TABLE Users; --")]
    [TestCase("admin'--")]
    [TestCase("1 UNION SELECT * FROM Users")]
    public async Task Register_Rejects_SqlInjection_Payloads(string payload)
    {
        var res = await _client.PostAsJsonAsync("/api/account/register",
            new RegisterRequest(payload, "attacker@example.com", "ValidP@ssw0rd123!"));
        Assert.That(res.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    [TestCase("x'; DROP TABLE Users; --@example.com")]
    [TestCase("' OR '1'='1@example.com")]
    public async Task Register_Rejects_SqlInjection_In_Email(string payload)
    {
        var res = await _client.PostAsJsonAsync("/api/account/register",
            new RegisterRequest("mallory", payload, "ValidP@ssw0rd123!"));
        Assert.That(res.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    [TestCase("' OR '1'='1", "x@y.zz")]
    [TestCase("bob", "x'; DROP TABLE Users; --@y.zz")]
    public async Task WebForm_Rejects_SqlInjection(string username, string email)
    {
        var res = await PostFormAsync(username, email);
        Assert.That(res.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    // ---------- XSS ----------

    [TestCase("<script>alert(1)</script>")]
    [TestCase("<iframe src='evil'>")]
    [TestCase("<img onerror=alert(1)>")]
    [TestCase("javascript:alert(1)")]
    public async Task Register_Rejects_Xss_Payloads(string payload)
    {
        var res = await _client.PostAsJsonAsync("/api/account/register",
            new RegisterRequest(payload, "attacker@example.com", "ValidP@ssw0rd123!"));
        Assert.That(res.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    [TestCase("<script>alert(1)</script>@example.com")]
    [TestCase("\"><img src=x onerror=alert(1)>@example.com")]
    [TestCase("javascript:alert(1)@example.com")]
    public async Task Register_Rejects_Xss_In_Email(string payload)
    {
        var res = await _client.PostAsJsonAsync("/api/account/register",
            new RegisterRequest("mallory", payload, "ValidP@ssw0rd123!"));
        Assert.That(res.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    [Test]
    public async Task WebForm_Reflects_Safe_Output_For_Hostile_Input()
    {
        var res  = await PostFormAsync("<script>alert(1)</script>", "x@y.z");
        var html = await res.Content.ReadAsStringAsync();

        Assert.That(res.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        Assert.That(html, Does.Not.Contain("<script>alert(1)</script>"));
    }

    [TestCase("<script>alert(1)</script>@example.com")]
    [TestCase("\"><svg/onload=alert(1)>@example.com")]
    public async Task WebForm_Rejects_Xss_In_Email_Without_Reflecting_It(string payload)
    {
        var res  = await PostFormAsync("bob", payload);
        var html = await res.Content.ReadAsStringAsync();

        Assert.That(res.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        Assert.That(html, Does.Not.Contain(payload));
        Assert.That(html, Does.Not.Contain("<script>"));
        Assert.That(html, Does.Not.Contain("<svg"));
    }

    [Test]
    public async Task WebForm_Valid_Input_Is_Echoed_On_Success()
    {
        var res  = await PostFormAsync("bob123", "bob@example.com");
        var html = await res.Content.ReadAsStringAsync();

        Assert.That(res.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(html, Does.Contain("bob123"));
        Assert.That(html, Does.Contain("bob@example.com"));
    }

    // Defense in depth: even if validation were bypassed, the success page encodes output.
    [Test]
    public void WebForm_Success_Page_Encodes_User_Values()
    {
        var html = WebFormEndpoints.RenderSuccess(
            "<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>");

        Assert.That(html, Does.Not.Contain("<script>alert(1)</script>"));
        Assert.That(html, Does.Not.Contain("<img"));
        Assert.That(html, Does.Contain("&lt;script&gt;alert(1)&lt;/script&gt;"));
        Assert.That(html, Does.Contain("&lt;img src=x onerror=alert(1)&gt;"));
    }

    private Task<HttpResponseMessage> PostFormAsync(string username, string email) =>
        _client.PostAsync("/submit", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["username"] = username,
            ["email"]    = email
        }));
}
