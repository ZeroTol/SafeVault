using NUnit.Framework;
using SafeVault.Helpers;

[TestFixture]
public class TestXssProtection
{
    [TestCase("<script>alert('XSS');</script>")]
    [TestCase("<iframe src='evil'></iframe>")]
    [TestCase("javascript:alert(1)")]
    [TestCase("<img onerror=alert(1)>")]
    public void Detects_Xss_Payloads(string payload) =>
        Assert.That(XssProtection.IsSafeInput(payload), Is.False);

    [TestCase("hello")]
    [TestCase("user_123")]
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