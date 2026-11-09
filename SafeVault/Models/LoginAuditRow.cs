namespace SafeVault.Models;

public record LoginAuditRow(string Username, string? IpAddress, string Outcome, DateTime CreatedUtc);