using SafeVault.Helpers;

[TestFixture]
public class TestInputValidation
{
    [TestCase("alice")]
    [TestCase("user_01")]
    [TestCase("john@home")]
    public void Accepts_Valid_Usernames(string input) =>
        Assert.That(ValidationHelpers.IsValidInput(input, "@_"), Is.True);

    [TestCase("")]
    [TestCase(null)]
    [TestCase("<script>")]
    [TestCase("drop table users")]
    [TestCase("bad name")]
    public void Rejects_Invalid_Usernames(string? input) =>
        Assert.That(ValidationHelpers.IsValidInput(input, "@_"), Is.False);

    [TestCase("test@example.com")]
    [TestCase("a.b+c@sub.domain.co")]
    public void Accepts_Valid_Emails(string email) =>
        Assert.That(ValidationHelpers.IsValidEmail(email), Is.True);

    [TestCase("not-an-email")]
    [TestCase("a@b")]
    [TestCase("a@b.c")]
    public void Rejects_Invalid_Emails(string email) =>
        Assert.That(ValidationHelpers.IsValidEmail(email), Is.False);
}