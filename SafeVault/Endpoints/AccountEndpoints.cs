using SafeVault.Helpers;
using SafeVault.Models.Contracts;
using SafeVault.Services;

namespace SafeVault.Endpoints;

public static class AccountEndpoints
{
    public static IEndpointRouteBuilder MapAccountEndpoints(this IEndpointRouteBuilder group)
    {
        group.MapPost("/register", RegisterAsync);
        group.MapPost("/login", LoginAsync);
        return group;
    }

    private static async Task<IResult> RegisterAsync(
        RegisterRequest req, IAuthService auth)
    {
        if (!ValidationHelpers.IsValidInput(req.Username) ||
            !ValidationHelpers.IsValidEmail(req.Email) ||
            !ValidationHelpers.IsValidPassword(req.Password) ||
            !XssProtection.IsSafeInput(req.Username) ||
            !XssProtection.IsSafeInput(req.Email))
        {
            return TypedResults.ValidationProblem(new Dictionary<string, string[]>
            {
                ["input"] = new[] { "Input failed validation (format or XSS markers)." }
            });
        }

        var ok = await auth.RegisterAsync(req.Username, req.Email, req.Password);
        return ok
            ? TypedResults.Created($"/api/account/users/{req.Username}")
            : TypedResults.Conflict(new { error = "Username already exists." });
    }

    private static async Task<IResult> LoginAsync(
        LoginRequest req, IAuthService auth)
    {
        if (!ValidationHelpers.IsValidInput(req.Username) ||
            !XssProtection.IsSafeInput(req.Username))
        {
            return TypedResults.BadRequest(new { error = "Invalid credentials format." });
        }

        var ok = await auth.LoginAsync(req.Username, req.Password);
        return ok
            ? TypedResults.Ok(new { message = "Authenticated." })
            : TypedResults.Unauthorized();
    }
}