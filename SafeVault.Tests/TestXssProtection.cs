using NUnit.Framework;
using SafeVault.Helpers;

[TestFixture]
public class TestXssProtection
{
    [TestCase("<script>alert('XSS');</script>")]
    [TestCase("<iframe src='evil'></iframe>")]
    [TestCase("javascript:alert(1)")]
    [TestCase("<img onerror=alert(1)>")]
    // Bypasses of the old substring blocklist:
    [TestCase("<img src=x onmouseover=alert(1)>")]
    [TestCase("<svg/onload=alert(1)>")]
    [TestCase("<a href='java\tscript:alert(1)'>x</a>")]
    [TestCase("&lt;script&gt;alert(1)&lt;/script&gt;")]
    [TestCase("&#106;avascript:alert(1)")]
    [TestCase("<body onload = alert(1)>")]
    public void Detects_Xss_Payloads(string payload) =>
        Assert.That(XssProtection.IsSafeInput(payload), Is.False);

    [TestCase("hello")]
    [TestCase("user_123")]
    [TestCase("jon@example.com")]
    [TestCase("salmon=tasty")]
    public void Accepts_Safe_Input(string input) =>
        Assert.That(XssProtection.IsSafeInput(input), Is.True);

    [Test]
    public void Encodes_Html()
    {
        var encoded = XssProtection.Encode("<script>");
        Assert.That(encoded, Does.Not.Contain("<script>"));
        Assert.That(encoded, Does.Contain("&lt;"));
    }
}