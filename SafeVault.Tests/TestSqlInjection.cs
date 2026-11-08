using SafeVault.Helpers;

[TestFixture]
public class TestSqlInjection
{
    [TestCase("'; DROP TABLE Users; --")]
    [TestCase("' OR '1'='1")]
    [TestCase("admin'--")]
    public void Blocks_Common_SqlInjection_Payloads(string payload)
    {
        Assert.That(ValidationHelpers.IsValidInput(payload, "@_"), Is.False);
    }

    [Test]
    public void Safe_Username_Passes_Allow_List()
    {
        Assert.That(ValidationHelpers.IsValidInput("normal_user", "@_"), Is.True);
    }
}