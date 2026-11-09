namespace SafeVault.Models.Contracts;

public record LoginResponse(string AccessToken, string TokenType, int ExpiresInSeconds, string Role);