using System.Security.Claims;
using SafeVault.Helpers;
using SafeVault.Models.Contracts;
using SafeVault.Services;

namespace SafeVault.Endpoints;

public static class AccountEndpoints
{
    public static IEndpointRouteBuilder MapAccountEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/account").WithTags("Account");

        group.MapPost("/register", RegisterAsync);
        group.MapPost("/login",    LoginAsync);
        group.MapGet ("/me",       MeAsync).RequireAuthorization();   // any authenticated user

        return app;
    }

    private static async Task<IResult> RegisterAsync(RegisterRequest req, IAuthService auth)
    {
        if (!ValidationHelpers.IsValidInput(req.Username) ||
            !ValidationHelpers.IsValidEmail(req.Email) ||
            !ValidationHelpers.IsValidPassword(req.Password) ||
            !XssProtection.IsSafeInput(req.Username) ||
            !XssProtection.IsSafeInput(req.Email))
            return TypedResults.ValidationProblem(new Dictionary<string, string[]>
                { ["input"] = ["Input failed validation."] });

        return await auth.RegisterAsync(req.Username, req.Email, req.Password)
            ? TypedResults.Created($"/api/account/users/{req.Username}")
            : TypedResults.Conflict(new { error = "Username already exists." });
    }

    private static async Task<IResult> LoginAsync(LoginRequest req, IAuthService auth)
    {
        if (!ValidationHelpers.IsValidInput(req.Username) ||
            !XssProtection.IsSafeInput(req.Username))
            return TypedResults.BadRequest(new { error = "Invalid credentials format." });

        var result = await auth.LoginAsync(req.Username, req.Password);
        return result is null ? TypedResults.Unauthorized() : TypedResults.Ok(result);
    }

    private static IResult MeAsync(ClaimsPrincipal user) =>
        TypedResults.Ok(new
        {
            userId = user.FindFirstValue(ClaimTypes.NameIdentifier) ?? user.FindFirstValue("sub"),
            name   = user.Identity?.Name,
            role   = user.FindFirstValue(ClaimTypes.Role)
        });
}